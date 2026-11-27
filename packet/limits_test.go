package packet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// slowConn serves stream one byte per Read and optionally blocks between
// bytes, simulating a client that dribbles a large packet byte by byte.
type slowConn struct {
	net.Conn
	mu      sync.Mutex
	data    []byte
	pos     int
	block   chan struct{} // non-nil: reads block until closed/never
	reads   atomic.Int64
	partial atomic.Int64
}

func (s *slowConn) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads.Add(1)
	if s.block != nil {
		<-s.block
	}
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	if len(p) > 1 {
		s.partial.Add(1)
		p = p[:1]
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}
func (s *slowConn) Write(p []byte) (int, error)      { return len(p), nil }
func (s *slowConn) Close() error                     { return nil }
func (s *slowConn) RemoteAddr() net.Addr             { return slowAddr("10.0.0.9:4321") }
func (s *slowConn) SetReadDeadline(time.Time) error  { return nil }
func (s *slowConn) SetWriteDeadline(time.Time) error { return nil }
func (s *slowConn) SetDeadline(time.Time) error      { return nil }

type slowAddr string

func (a slowAddr) Network() string { return "tcp" }
func (a slowAddr) String() string  { return string(a) }

// readerConn adapts an io.Reader to net.Conn for in-process read tests.
type readerConn struct {
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *readerConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *readerConn) Close() error                     { return nil }
func (c *readerConn) LocalAddr() net.Addr              { return nil }
func (c *readerConn) RemoteAddr() net.Addr             { return slowAddr("127.0.0.1:0") }
func (c *readerConn) SetDeadline(time.Time) error      { return nil }
func (c *readerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readerConn) SetWriteDeadline(time.Time) error { return nil }

// bigPacket builds a logical MySQL packet of total payload size n, split into
// 16MB continuation frames exactly like the wire protocol requires.
func bigPacket(t *testing.T, n int) []byte {
	t.Helper()
	var wire bytes.Buffer
	w := bufio.NewWriter(&wire)
	remaining := n
	seq := byte(0)
	for {
		chunk := min(remaining, mysql.MaxPayloadLen)
		hdr := []byte{byte(chunk), byte(chunk >> 8), byte(chunk >> 16), seq}
		_, err := w.Write(hdr)
		require.NoError(t, err)
		_, err = w.Write(make([]byte, chunk))
		require.NoError(t, err)
		seq++
		remaining -= chunk
		if chunk < mysql.MaxPayloadLen {
			break
		}
	}
	require.NoError(t, w.Flush())
	return wire.Bytes()
}

func TestMaxPacketSizeRejectsOversizedPacket(t *testing.T) {
	wire := bigPacket(t, 2*mysql.MaxPayloadLen+10) // ~32MB logical packet
	raw := &slowConn{Conn: nil, data: wire}
	c := NewBufferedConn(raw, 4096)
	c.SetMaxPacketSize(mysql.MaxPayloadLen) // one frame is the threshold

	_, err := c.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrPacketTooLarge), "got %v", err)
	require.True(t, errors.Is(err, mysql.ErrBadConn))
	require.True(t, c.isClosed(), "connection must be closed after oversize")

	// No further packet can be delivered on the disconnected connection.
	_, err = c.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, mysql.ErrBadConn))

	stats := c.ReadStats()
	require.EqualValues(t, 1, stats.OversizedRejects)
}

func TestMaxPacketSizeAllowsLargeResultWithinThreshold(t *testing.T) {
	const size = mysql.MaxPayloadLen + 5000 // spans two frames, within the cap
	wire := bigPacket(t, size)
	raw := &slowConn{data: wire}
	c := NewBufferedConn(raw, 4096)
	c.SetMaxPacketSize(2 * mysql.MaxPayloadLen)

	got, err := c.ReadPacket()
	require.NoError(t, err)
	require.Len(t, got, size)
	require.False(t, c.isClosed())
	require.EqualValues(t, size, c.ReadStats().TotalReadBytes)
}

func TestMaxPacketSizeAppliesToAlreadyBufferedData(t *testing.T) {
	// A whole oversized packet lands in bufio before any ReadPacket call:
	// the cap must still reject it, and no further appends happen.
	payload := make([]byte, 1000)
	wire := deadlinePacket(0, payload)
	c := NewBufferedConn(&readerConn{r: bytes.NewReader(wire)}, 4096)
	// Prime the bufio reader so the packet is fully buffered in memory.
	_, err := c.br.Peek(len(wire))
	require.NoError(t, err)
	require.Equal(t, len(wire), c.br.Buffered())

	c.SetMaxPacketSize(100)
	_, err = c.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrPacketTooLarge), "got %v", err)
	require.True(t, c.isClosed())
	// Buffered data was discarded on disconnect.
	require.Zero(t, c.br.Buffered())
}

func TestMaxPacketSizeZeroMeansUnlimited(t *testing.T) {
	wire := bigPacket(t, mysql.MaxPayloadLen+10)
	c := NewBufferedConn(&readerConn{r: bytes.NewReader(wire)}, 4096)
	require.Zero(t, c.MaxPacketSize())
	got, err := c.ReadPacket()
	require.NoError(t, err)
	require.Len(t, got, mysql.MaxPayloadLen+10)
}

func TestReadLimiterSharedBudgetNotMonopolized(t *testing.T) {
	// Two connections share a 2KB budget. Each packet is 1KB; neither
	// connection may reserve more than its own in-flight chunk, and after a
	// connection exhausts the budget it is disconnected while the other keeps
	// working once budget is released.
	const budget = 2048
	limiter := NewReadLimiter(budget)
	require.Equal(t, budget, limiter.Limit())

	pkt := deadlinePacket(0, make([]byte, 1024))

	c1 := NewBufferedConn(&readerConn{r: bytes.NewReader(append(pkt, pkt...))}, 4096)
	c1.SetReadLimiter(limiter)
	c2 := NewBufferedConn(&readerConn{r: bytes.NewReader(append(pkt, pkt...))}, 4096)
	c2.SetReadLimiter(limiter)

	// Both read their first packet: total in flight never exceeds the budget.
	got1, err := c1.ReadPacket()
	require.NoError(t, err)
	require.Len(t, got1, 1024)
	require.EqualValues(t, 0, limiter.Used(), "budget released after delivery")

	got2, err := c2.ReadPacket()
	require.NoError(t, err)
	require.Len(t, got2, 1024)
	require.EqualValues(t, 0, limiter.Used())
}

func TestReadLimiterExhaustionDisconnectsOnlyGreedyConn(t *testing.T) {
	// A tiny shared budget and a 16KB read chunk: the first connection cannot
	// acquire its chunk and must be failed, while a second connection with no
	// limiter attached is unaffected.
	limiter := NewReadLimiter(64)
	greedy := NewBufferedConn(&readerConn{r: bytes.NewReader(deadlinePacket(0, make([]byte, 4096)))}, 4096)
	greedy.SetReadLimiter(limiter)

	_, err := greedy.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrReadLimitExhausted), "got %v", err)
	require.True(t, greedy.isClosed())

	other := NewBufferedConn(&readerConn{r: bytes.NewReader(deadlinePacket(0, []byte("fine")))}, 4096)
	got, err := other.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, []byte("fine"), got)
}

func TestReadLimiterReleaseOnClose(t *testing.T) {
	limiter := NewReadLimiter(1 << 20)
	require.True(t, limiter.tryAcquire(1000))
	require.EqualValues(t, 1000, limiter.Used())
	limiter.release(1000)
	require.EqualValues(t, 0, limiter.Used())
	// Over-release is a no-op rather than corrupting the counter.
	limiter.release(500)
	require.EqualValues(t, 0, limiter.Used())
}

func TestIdleVsMidPacketTimeoutDistinctErrors(t *testing.T) {
	t.Run("idle timeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		c := NewConnWithTimeout(client, 30*time.Millisecond, 0, 4096)
		_, err := c.ReadPacket()
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrReadIdleTimeout), "got %v", err)
		require.False(t, errors.Is(err, ErrReadPacketTimeout))
		require.EqualValues(t, 1, c.ReadStats().IdleTimeouts)
		require.EqualValues(t, 0, c.ReadStats().PacketTimeouts)
	})

	t.Run("mid-packet timeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer server.Close()
		c := NewConnWithTimeout(client, 30*time.Millisecond, 0, 4096)
		go func() {
			// Header promises 100 bytes; only 10 payload bytes ever arrive.
			_, _ = server.Write(deadlinePacket(0, make([]byte, 100))[:14])
		}()
		_, err := c.ReadPacket()
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrReadPacketTimeout), "got %v", err)
		require.False(t, errors.Is(err, ErrReadIdleTimeout))
		require.EqualValues(t, 1, c.ReadStats().PacketTimeouts)
		require.EqualValues(t, 0, c.ReadStats().IdleTimeouts)
	})
}

func TestTimeoutDisconnectReleasesBuffersAndBlocksDelivery(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := NewConnWithTimeout(client, 30*time.Millisecond, 0, 4096)
	go func() {
		_, _ = server.Write([]byte{100, 0, 0, 0, 'a', 'b'})
	}()
	_, err := c.ReadPacket()
	require.Error(t, err)
	require.True(t, c.isClosed())
	require.Zero(t, c.ReadStats().CurrentPacketBytes)

	// Even if the rest of the packet arrived meanwhile, nothing is delivered.
	_, err = c.ReadPacket()
	require.Error(t, err)
}

type logCaptureHandler struct {
	mu    sync.Mutex
	attrs []slog.Attr
	msg   string
}

func (h *logCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *logCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msg = r.Message
	r.Attrs(func(a slog.Attr) bool { h.attrs = append(h.attrs, a); return true })
	return nil
}
func (h *logCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *logCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func TestDisconnectLogRecordsBytesAndAddr(t *testing.T) {
	h := &logCaptureHandler{}
	logger := slog.New(h)
	raw := &slowConn{data: deadlinePacket(0, make([]byte, 1000))}
	c := NewBufferedConn(raw, 4096)
	c.SetReadLogger(logger)
	c.SetMaxPacketSize(100)

	_, err := c.ReadPacket()
	require.Error(t, err)

	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(t, h.msg)
	got := map[string]any{}
	for _, a := range h.attrs {
		got[a.Key] = a.Value.Any()
	}
	require.Contains(t, got, "read_bytes")
	require.Equal(t, "10.0.0.9:4321", got["remote_addr"])
	require.Contains(t, got, "reason")
}

func TestReadStatsProgress(t *testing.T) {
	// One-byte-at-a-time server. Buffered: bufio absorbs the dribbling but the
	// underlying read count still reveals the slow peer. Unbuffered (TLS-style
	// conn): every chunk is short, so PartialReads accumulates directly.
	wire := deadlinePacket(0, bytes.Repeat([]byte("x"), 200))

	t.Run("buffered", func(t *testing.T) {
		raw := &slowConn{data: wire}
		c := NewConnWithTimeout(raw, 0, 0, 4096)
		got, err := c.ReadPacket()
		require.NoError(t, err)
		require.Len(t, got, 200)

		stats := c.ReadStats()
		require.EqualValues(t, 200, stats.TotalReadBytes)
		require.Greater(t, stats.Reads, uint64(1), "byte-at-a-time peer needs many transport reads")
		require.EqualValues(t, 0, stats.CurrentPacketBytes)
		require.False(t, stats.CreatedAt.IsZero())

		c.ResetReadStats()
		require.Zero(t, c.ReadStats().TotalReadBytes)
		require.Zero(t, c.ReadStats().Reads)
	})

	t.Run("unbuffered partial reads", func(t *testing.T) {
		raw := &slowConn{data: wire}
		c := NewTLSConn(raw)
		got, err := c.ReadPacket()
		require.NoError(t, err)
		require.Len(t, got, 200)

		stats := c.ReadStats()
		require.Greater(t, stats.PartialReads, uint64(0), "short reads surface without bufio")
		require.EqualValues(t, 200, stats.TotalReadBytes)
	})
}

func TestOversizedContinuationFrameRejectedOnTotalSize(t *testing.T) {
	// Cap allows one frame but not two: the second frame's header must trip
	// the limit even though each frame individually is exactly MaxPayloadLen.
	wire := bigPacket(t, 2*mysql.MaxPayloadLen)
	raw := &slowConn{data: wire}
	c := NewBufferedConn(raw, 4096)
	c.SetMaxPacketSize(mysql.MaxPayloadLen + 1024)

	_, err := c.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrPacketTooLarge), "got %v", err)
	require.True(t, c.isClosed())
}

// TestSharedBudgetE2EOnlyGreedyConnectionDisconnects drives two real
// connections over net.Pipe against one shared budget. The connection whose
// packet cannot fit is disconnected; the other keeps reading once budget is
// released, proving the shared cap cannot be monopolized by one peer.
func TestSharedBudgetE2EOnlyGreedyConnectionDisconnects(t *testing.T) {
	limiter := NewReadLimiter(256)

	// Victim: a well-behaved small packet.
	victimClient, victimServer := net.Pipe()
	defer victimServer.Close()
	victim := NewConnWithTimeout(victimClient, 0, 0, 4096)
	victim.SetReadLimiter(limiter)

	// Greedy: a header promising far more than the whole budget.
	greedyClient, greedyServer := net.Pipe()
	defer greedyServer.Close()
	greedy := NewConnWithTimeout(greedyClient, 0, 0, 4096)
	greedy.SetReadLimiter(limiter)

	greedyErr := make(chan error, 1)
	go func() {
		// Payload larger than the 256-byte budget: the first 16KB chunk
		// acquisition fails and this connection is closed.
		_, err := greedy.ReadPacket()
		greedyErr <- err
	}()
	go func() {
		_, _ = greedyServer.Write(deadlinePacket(0, make([]byte, 4096)))
	}()

	select {
	case err := <-greedyErr:
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrReadLimitExhausted), "got %v", err)
		require.True(t, greedy.isClosed())
	case <-time.After(2 * time.Second):
		t.Fatal("greedy connection was not disconnected")
	}

	// The shared budget must be fully released so the victim is unaffected.
	require.EqualValues(t, 0, limiter.Used())
	require.EqualValues(t, 0, greedy.reserved.Load())
	go func() {
		_, _ = victimServer.Write(deadlinePacket(0, []byte("ok")))
	}()
	got, err := victim.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), got)
}

// TestTimeoutReleasesSharedBudget verifies that a mid-packet timeout hands all
// in-flight budget back to the shared pool rather than leaking it.
func TestTimeoutReleasesSharedBudget(t *testing.T) {
	limiter := NewReadLimiter(1 << 20)
	client, server := net.Pipe()
	defer server.Close()
	c := NewConnWithTimeout(client, 30*time.Millisecond, 0, 4096)
	c.SetReadLimiter(limiter)

	go func() {
		// Header plus a few bytes, then silence: mid-packet timeout.
		_, _ = server.Write([]byte{100, 0, 0, 0, 'a', 'b', 'c'})
	}()
	_, err := c.ReadPacket()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrReadPacketTimeout), "got %v", err)
	require.True(t, c.isClosed())
	require.EqualValues(t, 0, limiter.Used(), "timeout must release all shared budget")
	require.EqualValues(t, 0, c.reserved.Load())
}

func TestUnlimitedSlowClientStillReadsWholePacket(t *testing.T) {
	// The default (no cap, no timeout) must still reassemble a byte-at-a-time
	// multi-frame packet.
	wire := bigPacket(t, mysql.MaxPayloadLen+5)
	raw := &slowConn{data: wire}
	c := NewBufferedConn(raw, 4096)
	got, err := c.ReadPacket()
	require.NoError(t, err)
	require.Len(t, got, mysql.MaxPayloadLen+5)
}

func TestBufferedBytesAccounting(t *testing.T) {
	first := deadlinePacket(0, []byte("a"))
	second := deadlinePacket(1, make([]byte, 500))
	stream := append(first, second...)
	c := NewBufferedConn(&readerConn{r: bytes.NewReader(stream)}, 4096)
	_, err := c.br.Peek(len(stream))
	require.NoError(t, err)
	require.GreaterOrEqual(t, c.ReadStats().BufferedBytes, uint64(len(stream)))

	got, err := c.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, []byte("a"), got)
}

// bytesReaderOnly adapts bytes.Reader under the name used in earlier tests.
