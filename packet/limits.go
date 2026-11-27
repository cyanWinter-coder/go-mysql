package packet

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// errReaderClosed backs the empty reader installed when buffered data is
// dropped on a forced disconnect.
var errReaderClosed = errors.New("packet read buffer discarded: connection closed")

// Sentinel errors reported by the bounded read path. All of them are wrapped
// around mysql.ErrBadConn as well, so callers that discard any connection
// whose read fails keep working; use errors.Is to distinguish the cause.
var (
	// ErrPacketTooLarge means a packet exceeded the per-connection
	// MaxPacketSize configured on the Conn. The offending connection is closed.
	ErrPacketTooLarge = newPacketSentinel("packet exceeds maximum allowed size")

	// ErrReadLimitExhausted means the process-wide shared read budget
	// (ReadLimiter) had no capacity for the bytes a connection needed. Only the
	// connection that could not acquire budget is closed; others keep working.
	ErrReadLimitExhausted = newPacketSentinel("shared read memory limit exhausted")

	// ErrReadIdleTimeout means no byte at all arrived within ReadTimeout while
	// waiting for the next packet (or its header): a stalled/idle peer.
	ErrReadIdleTimeout = newPacketSentinel("idle read timeout")

	// ErrReadPacketTimeout means the peer went silent mid-packet: some bytes
	// of the current packet already arrived, but the rest did not arrive
	// within ReadTimeout. Distinct from ErrReadIdleTimeout so operators can
	// tell a slow client apart from a stalled one.
	ErrReadPacketTimeout = newPacketSentinel("mid-packet read timeout")
)

// ReadStats is a point-in-time snapshot of a Conn's read progress. Upper layers
// use it to decide whether a peer is too slow (low ReadBytesPerSec, many
// partial reads) or the server itself cannot keep up.
type ReadStats struct {
	// TotalReadBytes is the number of payload bytes delivered to callers
	// since the Conn was created (or ReadStats were last reset).
	TotalReadBytes uint64
	// BufferedBytes is the number of bytes currently held on behalf of this
	// connection: the in-flight packet plus data parked in the bufio reader.
	BufferedBytes uint64
	// CurrentPacketBytes is the progress through the packet currently being
	// read: 0 while waiting for a fresh header, growing as chunks arrive.
	CurrentPacketBytes uint64
	// CurrentPacketExpected is the total payload size of the packet currently
	// being read once its header has been parsed, else 0. Continuation frames
	// are accounted for, so a packet spanning multiple frames reports its
	// full logical size.
	CurrentPacketExpected uint64
	// Reads counts underlying transport Read calls.
	Reads uint64
	// PartialReads counts Read calls that returned data but did not complete
	// the chunk they were asked for: a high rate means the peer dribbles
	// bytes instead of sending whole packets.
	PartialReads uint64
	// OversizedRejects counts packets rejected for exceeding MaxPacketSize.
	OversizedRejects uint64
	// Timeouts counts read timeouts, split into idle and mid-packet ones.
	IdleTimeouts   uint64
	PacketTimeouts uint64
	// CreatedAt is when the Conn (or its stats) was created/reset.
	CreatedAt time.Time
}

// ReadLimiter is a process-wide weighted byte budget shared by connections.
// Each connection only ever holds budget for bytes it has pulled off the wire
// but not yet delivered, so a single connection can monopolize at most its own
// MaxPacketSize of the shared budget: many slow connections cannot combine into
// unbounded memory, and one connection cannot starve the others.
//
// A ReadLimiter is safe for concurrent use. The zero value is not usable;
// create one with NewReadLimiter.
type ReadLimiter struct {
	limit int64
	used  atomic.Int64
}

// NewReadLimiter creates a shared budget of limit bytes. A non-positive limit
// disables limiting (Acquire always succeeds).
func NewReadLimiter(limit int) *ReadLimiter {
	l := &ReadLimiter{}
	l.limit = int64(limit)
	return l
}

// Limit returns the configured budget, or 0 when limiting is disabled.
func (l *ReadLimiter) Limit() int {
	if l == nil {
		return 0
	}
	return int(l.limit)
}

// Used returns the bytes currently reserved across all connections.
func (l *ReadLimiter) Used() int64 {
	if l == nil {
		return 0
	}
	return l.used.Load()
}

// Acquire reserves n bytes of the shared budget, reporting whether the
// reservation succeeded. It is non-blocking: a false result means the budget
// is exhausted and the caller must not treat the bytes as admitted (the
// packet layer disconnects such a connection). A disabled limiter (nil or
// non-positive limit) always returns true.
func (l *ReadLimiter) Acquire(n int) bool {
	return l.tryAcquire(n)
}

// Release hands n bytes of budget back. It is safe to call without a matching
// Acquire and never drives Used below zero.
func (l *ReadLimiter) Release(n int) {
	l.release(n)
}

// tryAcquire reserves n bytes of the shared budget. It never blocks: when the
// budget is exhausted it returns false instead of queueing, so one greedy
// connection cannot hold up unrelated connections (they get budget as soon as
// the holder releases it).
func (l *ReadLimiter) tryAcquire(n int) bool {
	if l == nil || l.limit <= 0 || n <= 0 {
		return true
	}
	for {
		cur := l.used.Load()
		if cur+int64(n) > l.limit {
			return false
		}
		if l.used.CompareAndSwap(cur, cur+int64(n)) {
			return true
		}
	}
}

// release hands budget back. Releasing more than was acquired is a no-op.
func (l *ReadLimiter) release(n int) {
	if l == nil || l.limit <= 0 || n <= 0 {
		return
	}
	for {
		cur := l.used.Load()
		dec := int64(n)
		if dec > cur {
			dec = cur
		}
		if l.used.CompareAndSwap(cur, cur-dec) {
			return
		}
	}
}

// readStatsCounters holds the per-connection read progress. Every field is an
// atomic, so the hot read path takes no lock and ReadStats can snapshot it
// concurrently with reads.
type readStatsCounters struct {
	totalReadBytes      atomic.Uint64
	currentPacketBytes  atomic.Uint64
	currentPacketExpect atomic.Uint64
	reads               atomic.Uint64
	partialReads        atomic.Uint64
	oversizedRejects    atomic.Uint64
	idleTimeouts        atomic.Uint64
	packetTimeouts      atomic.Uint64
	createdAt           atomic.Int64 // unix nano
}

func (s *readStatsCounters) init() {
	s.createdAt.Store(time.Now().UnixNano())
}

func (s *readStatsCounters) snapshot(buffered uint64) ReadStats {
	return ReadStats{
		TotalReadBytes:        s.totalReadBytes.Load(),
		BufferedBytes:         buffered,
		CurrentPacketBytes:    s.currentPacketBytes.Load(),
		CurrentPacketExpected: s.currentPacketExpect.Load(),
		Reads:                 s.reads.Load(),
		PartialReads:          s.partialReads.Load(),
		OversizedRejects:      s.oversizedRejects.Load(),
		IdleTimeouts:          s.idleTimeouts.Load(),
		PacketTimeouts:        s.packetTimeouts.Load(),
		CreatedAt:             time.Unix(0, s.createdAt.Load()),
	}
}

// configMu guards the read-protection settings that can be changed between
// packets (maxPacketSize, limiter, logger) and the closed flag.
type limitConfig struct {
	mu            sync.RWMutex
	maxPacketSize int
	limiter       *ReadLimiter
	logger        *slog.Logger
	closed        bool
}

// SetMaxPacketSize bounds the total payload size of any packet read on this
// connection, including packets split over multiple 16MB continuation frames
// and bytes already parked in the read buffer. A non-positive value removes
// the limit (the default): legitimate oversized result sets keep working, and
// callers opt into an explicit threshold. Applies to the next packet read.
func (c *Conn) SetMaxPacketSize(maxBytes int) {
	c.limitCfg.mu.Lock()
	c.limitCfg.maxPacketSize = maxBytes
	c.limitCfg.mu.Unlock()
}

// MaxPacketSize returns the configured per-connection packet size limit, or 0
// when unlimited.
func (c *Conn) MaxPacketSize() int {
	c.limitCfg.mu.RLock()
	defer c.limitCfg.mu.RUnlock()
	return c.limitCfg.maxPacketSize
}

// SetReadLimiter attaches a process-wide shared read budget. Budget is only
// held for bytes pulled from the wire but not yet delivered, so a connection
// can reserve at most its own MaxPacketSize (or one read chunk when that is
// unset) and can never monopolize the shared budget. Pass nil to detach.
func (c *Conn) SetReadLimiter(l *ReadLimiter) {
	c.limitCfg.mu.Lock()
	c.limitCfg.limiter = l
	c.limitCfg.mu.Unlock()
}

// ReadLimiter returns the attached shared budget, or nil.
func (c *Conn) ReadLimiter() *ReadLimiter {
	c.limitCfg.mu.RLock()
	defer c.limitCfg.mu.RUnlock()
	return c.limitCfg.limiter
}

// SetReadLogger installs the logger used to record forced disconnects. Every
// disconnect caused by a size limit, exhausted shared budget, or read timeout
// is logged with the reason, the bytes already read, and the peer address, so
// malicious oversized packets can be told apart from legitimate large result
// sets. Pass nil (the default) to disable logging.
func (c *Conn) SetReadLogger(logger *slog.Logger) {
	c.limitCfg.mu.Lock()
	c.limitCfg.logger = logger
	c.limitCfg.mu.Unlock()
}

// ReadStats returns a consistent snapshot of this connection's read progress.
// BufferedBytes additionally reports data parked in the read buffer.
func (c *Conn) ReadStats() ReadStats {
	var buffered uint64
	if c.br != nil {
		buffered = uint64(c.br.Buffered())
	}
	buffered += c.stats.currentPacketBytes.Load()
	return c.stats.snapshot(buffered)
}

// ResetReadStats zeroes every read counter and restarts the creation clock.
func (c *Conn) ResetReadStats() {
	c.stats.totalReadBytes.Store(0)
	c.stats.currentPacketBytes.Store(0)
	c.stats.currentPacketExpect.Store(0)
	c.stats.reads.Store(0)
	c.stats.partialReads.Store(0)
	c.stats.oversizedRejects.Store(0)
	c.stats.idleTimeouts.Store(0)
	c.stats.packetTimeouts.Store(0)
	c.stats.createdAt.Store(time.Now().UnixNano())
}

func (c *Conn) maxPacketSizeLocked() int {
	c.limitCfg.mu.RLock()
	defer c.limitCfg.mu.RUnlock()
	return c.limitCfg.maxPacketSize
}

func (c *Conn) readLimiterLocked() *ReadLimiter {
	c.limitCfg.mu.RLock()
	defer c.limitCfg.mu.RUnlock()
	return c.limitCfg.limiter
}

func (c *Conn) isClosed() bool {
	c.limitCfg.mu.RLock()
	defer c.limitCfg.mu.RUnlock()
	return c.limitCfg.closed
}

// failRead enforces a read-protection violation: it records the cause, logs
// the forced disconnect with the bytes already read and the peer address,
// releases every reservation held by this connection, drops buffered bytes so
// their memory can be reclaimed, and closes the transport. Afterwards no
// packet — including one fully parsed but not yet handed out — can be
// delivered, because every further read fails fast on the closed flag.
func (c *Conn) failRead(cause error) error {
	c.limitCfg.mu.Lock()
	if c.limitCfg.closed {
		c.limitCfg.mu.Unlock()
		return cause
	}
	c.limitCfg.closed = true
	logger := c.limitCfg.logger
	c.limitCfg.mu.Unlock()

	readBytes := c.stats.currentPacketBytes.Load()
	if logger != nil {
		logger.Error("closing connection: read protection triggered",
			slog.Any("reason", cause),
			slog.Uint64("read_bytes", readBytes),
			slog.Uint64("packet_expected", c.stats.currentPacketExpect.Load()),
			slog.String("remote_addr", c.remoteAddrString()),
		)
	}

	// Release everything this connection still owes the shared budget.
	if held := c.reserved.Swap(0); held > 0 {
		c.readLimiterLocked().release(int(held))
	}
	// Drop buffered data so a partial/oversized packet is never retained.
	if c.br != nil {
		c.br.Reset(emptyReader{})
	}
	c.stats.currentPacketBytes.Store(0)
	c.stats.currentPacketExpect.Store(0)

	_ = c.Close()
	return cause
}

// remoteAddrString never panics on test doubles that leave the embedded
// net.Conn nil.
func (c *Conn) remoteAddrString() string {
	if c.Conn == nil || c.RemoteAddr() == nil {
		return "unknown"
	}
	return c.RemoteAddr().String()
}

// emptyReader makes the bufio.Reader discard its buffer on Reset without
// touching the underlying transport (which is being closed anyway).
type emptyReader struct{}

func (emptyReader) Read(p []byte) (int, error) { return 0, errReaderClosed }

// countingReader wraps the transport so every raw Read is visible to the
// read stats. ReadAtLeast only reports the aggregate of several Reads and
// cannot tell a dribbling peer (short chunk, no error) from a streaming one;
// the individual Read return is where that distinction exists.
type countingReader struct {
	c *Conn
	r io.Reader
}

func (cr countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.c.stats.reads.Add(1)
	// A short, non-terminal read: the transport had fewer than len(p) bytes
	// ready but is not at EOF or in error. That is the signature of a peer
	// sending a large packet in tiny pieces. EOF (n==0) and error-terminated
	// reads are connection events, counted by their respective counters.
	if n > 0 && n < len(p) && err == nil {
		cr.c.stats.partialReads.Add(1)
	}
	return n, err
}

// packetLimitError is the concrete type behind the read-protection
// sentinels. Its Is method lets a single returned error match both its own
// cause sentinel and mysql.ErrBadConn, so existing callers that discard any
// bad connection keep working while new callers can distinguish why it was
// closed.
type packetLimitError struct {
	sentinel *packetLimitError
	msg      string
}

func (e *packetLimitError) Error() string { return e.msg }

// Cause makes pingcap/errors (whose Unwrap only understands the causer
// interface, not the stdlib Unwrap) follow the chain to the sentinel, so the
// error stays discoverable after errors.Wrapf in the read path. A root
// sentinel returns nil: returning itself would make WalkDeep/Cause loop.
func (e *packetLimitError) Cause() error {
	if e.sentinel == e {
		return nil
	}
	return e.sentinel
}

// Unwrap mirrors Cause for the standard-library error chain.
func (e *packetLimitError) Unwrap() error {
	if e.sentinel == e {
		return nil
	}
	return e.sentinel
}

func (e *packetLimitError) Is(target error) bool {
	switch target {
	case mysql.ErrBadConn:
		return true
	default:
		if t, ok := target.(*packetLimitError); ok {
			return t == e.sentinel || t == e
		}
		return false
	}
}

func newPacketSentinel(msg string) *packetLimitError {
	e := &packetLimitError{msg: msg}
	e.sentinel = e
	return e
}

// newPacketError annotates a sentinel with context while preserving both the
// errors.Is chain (sentinel + ErrBadConn) and the sentinel's message text.
func newPacketError(sentinel *packetLimitError, context string) error {
	return &packetLimitError{
		sentinel: sentinel,
		msg:      sentinel.msg + ": " + context,
	}
}
