package packet

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	goErrors "errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/compress"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/klauspost/compress/zstd"
	"github.com/pingcap/errors"
)

const (
	MinCompressionLength = 50
	DefaultBufferSize    = 16 * 1024
	// DefaultReadBufferSize is the bufio.Reader size used by NewConn and
	// EnableReadBuffering.
	DefaultReadBufferSize = 64 * 1024
)

// Conn is the base class to handle MySQL protocol.
type Conn struct {
	net.Conn

	readTimeout  time.Duration
	writeTimeout time.Duration

	// Buffered reader for net.Conn in Non-TLS connection only to address replication performance issue.
	// See https://github.com/go-mysql-org/go-mysql/pull/422 for more details.
	br     *bufio.Reader
	reader io.Reader

	// Buffered writer, enabled via EnableWriteBuffering.
	bw *bufio.Writer

	copyNBuf []byte

	header [4]byte

	Sequence uint8

	Compression uint8

	CompressedSequence uint8

	// syncSequence is set after writing with compression and consumed by the
	// next read, which first continues the packet sequence from the
	// compressed sequence (see syncSequenceForRead).
	syncSequence bool

	// syncWriteSequence is the same for the other direction: set after reading
	// with compression and consumed by the next write (see
	// syncSequenceForWrite).
	syncWriteSequence bool

	compressedHeader [7]byte

	compressedReader io.Reader

	// Read-protection state. See limits.go: limitCfg carries the configurable
	// per-connection packet cap, the optional process-wide shared budget and
	// the closed flag; stats is the upper-layer-visible read progress; reserved
	// counts bytes this Conn currently owes the shared ReadLimiter.
	limitCfg limitConfig
	stats    readStatsCounters
	reserved atomic.Int64
}

func NewConn(conn net.Conn) *Conn {
	return NewBufferedConn(conn, DefaultReadBufferSize)
}

func NewBufferedConn(conn net.Conn, bufferSize int) *Conn {
	c := new(Conn)
	c.Conn = conn

	c.br = bufio.NewReaderSize(countingReader{c, c}, bufferSize)
	c.reader = c.br

	c.copyNBuf = make([]byte, DefaultBufferSize)
	c.stats.init()

	return c
}

func NewConnWithTimeout(conn net.Conn, readTimeout, writeTimeout time.Duration, bufferSize int) *Conn {
	c := NewBufferedConn(conn, bufferSize)
	c.readTimeout = readTimeout
	c.writeTimeout = writeTimeout
	return c
}

func NewTLSConn(conn net.Conn) *Conn {
	c := new(Conn)
	c.Conn = conn

	c.reader = countingReader{c, c}

	c.copyNBuf = make([]byte, DefaultBufferSize)
	c.stats.init()

	return c
}

func NewTLSConnWithTimeout(conn net.Conn, readTimeout, writeTimeout time.Duration) *Conn {
	c := NewTLSConn(conn)
	c.readTimeout = readTimeout
	c.writeTimeout = writeTimeout
	return c
}

// EnableReadBuffering wraps subsequent reads in a bufio.Reader of the given
// size. Conns created via NewTLSConn start unbuffered because the peer may
// still upgrade the transport to TLS during the handshake; call this once the
// handshake completes, and only between packets. No-op if reads are already
// buffered or bufferSize is not positive.
func (c *Conn) EnableReadBuffering(bufferSize int) {
	if c.br != nil || bufferSize <= 0 {
		return
	}
	c.br = bufio.NewReaderSize(countingReader{c, c}, bufferSize)
	c.reader = c.br
}

// connWriter adapts the deadline-setting write path to io.Writer so a
// bufio.Writer can sit on top of it.
type connWriter struct{ c *Conn }

func (w connWriter) Write(b []byte) (int, error) {
	return w.c.writeDirect(b)
}

// EnableWriteBuffering makes WritePacket accumulate packets in a buffer of the
// given size instead of issuing one write(2) each. Buffered data reaches the
// wire when the buffer fills, on Flush, or before any ReadPacket* call (so
// request/response flows cannot deadlock). Callers that stream packets without
// reading must Flush after each logical unit; Close does not flush. No-op if
// already enabled or bufferSize is not positive.
func (c *Conn) EnableWriteBuffering(bufferSize int) {
	if c.bw != nil || bufferSize <= 0 {
		return
	}
	c.bw = bufio.NewWriterSize(connWriter{c}, bufferSize)
}

// Flush writes any buffered packets to the underlying connection. It is a
// no-op when write buffering is not enabled.
func (c *Conn) Flush() error {
	if c.bw == nil {
		return nil
	}
	if err := c.bw.Flush(); err != nil {
		return errors.Wrapf(mysql.ErrBadConn, "Flush failed. err %v", err)
	}
	return nil
}

// BufferedPacketSize returns the next complete uncompressed packet's payload
// size, or -1 if reading it may require network I/O. It never fills the buffer
// or consumes data, and must only be called by the owner of packet reads.
// A maximum-length packet may have continuation packets, so it is not eligible.
func (c *Conn) BufferedPacketSize() int {
	if c.Compression != mysql.MYSQL_COMPRESS_NONE || c.br == nil || c.br.Buffered() < 4 {
		return -1
	}
	header, _ := c.br.Peek(4)
	size := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if size == mysql.MaxPayloadLen || c.br.Buffered() < 4+size {
		return -1
	}
	return size
}

func (c *Conn) ReadPacket() ([]byte, error) {
	return c.ReadPacketReuseMem(nil)
}

func (c *Conn) ReadPacketReuseMem(dst []byte) ([]byte, error) {
	if err := c.checkReadable(); err != nil {
		return nil, err
	}
	// Here we use `sync.Pool` to avoid allocate/destroy buffers frequently.
	buf := utils.BytesBufferGet()
	defer func() {
		utils.BytesBufferPut(buf)
	}()

	// Sync before reading the first compressed header below, which advances
	// CompressedSequence: the reply continues from the value our write left.
	c.syncSequenceForRead()

	// compressedReader is reset to nil after each WritePacket, so a nil reader here means
	// we're at the start of a new compressed frame and need to read its header. While a
	// frame still has buffered packets to hand out, we reuse the existing reader rather
	// than consuming another frame header. (newCompressedPacketReader never returns a nil
	// reader, so its nilness fully tracks whether a frame read is in progress.)
	if c.Compression != mysql.MYSQL_COMPRESS_NONE && c.compressedReader == nil {
		var err error
		c.compressedReader, err = c.newCompressedPacketReader()
		if err != nil {
			return nil, err
		}
	}

	if err := c.ReadPacketTo(buf); err != nil {
		// A failed read never returns buffered data: return the pool entry
		// straight away so its backing array is reclaimable.
		buf.Reset()
		return nil, errors.Trace(err)
	}

	readBytes := buf.Bytes()
	readSize := len(readBytes)
	var result []byte
	if len(dst) > 0 {
		result = append(dst, readBytes...)
		// if read block is big, do not cache buf anymore
		if readSize > utils.TooBigBlockSize {
			buf = nil
		}
	} else {
		if readSize > utils.TooBigBlockSize {
			// if read block is big, use read block as result and do not cache buf anymore
			result = readBytes
			buf = nil
		} else {
			result = append(dst, readBytes...)
		}
	}

	// Delivered bytes count toward the connection's lifetime progress.
	c.stats.totalReadBytes.Add(uint64(readSize))
	return result, nil
}

// checkReadable fails fast once the Conn has been force-closed by a read
// protection rule: a packet fully parsed before the disconnect must never be
// handed to an upper layer afterwards, and partial packets can never resume.
func (c *Conn) checkReadable() error {
	if c.isClosed() {
		return errors.Wrapf(mysql.ErrBadConn, "%s: connection already closed", errReaderClosed)
	}
	return nil
}

// newCompressedPacketReader creates a new compressed packet reader.
func (c *Conn) newCompressedPacketReader() (io.Reader, error) {
	// The peer may be waiting on our buffered output before it sends more.
	if err := c.Flush(); err != nil {
		return nil, err
	}
	if c.readTimeout != 0 {
		if err := c.SetReadDeadline(utils.Now().Add(c.readTimeout)); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(c.reader, c.compressedHeader[:7]); err != nil {
		// Keep the idle-vs-mid-packet distinction on the compressed path:
		// waiting for a frame header with no packet bytes in flight is idle.
		classified := c.classifyReadTimeout(err)
		if isReadProtectionError(classified) {
			return nil, c.failRead(classified)
		}
		return nil, errors.Wrapf(mysql.ErrBadConn, "io.ReadFull(compressedHeader) failed. err %v", classified)
	}

	compressedSequence := c.compressedHeader[3]
	if compressedSequence != c.CompressedSequence {
		return nil, errors.Errorf("invalid compressed sequence %d != %d",
			compressedSequence, c.CompressedSequence)
	}
	// Like the packet sequence, the compressed sequence is shared by both
	// directions within a command: the next frame, read or written, uses the
	// following number.
	c.CompressedSequence++

	compressedLength := int(uint32(c.compressedHeader[0]) | uint32(c.compressedHeader[1])<<8 | uint32(c.compressedHeader[2])<<16)
	uncompressedLength := int(uint32(c.compressedHeader[4]) | uint32(c.compressedHeader[5])<<8 | uint32(c.compressedHeader[6])<<16)

	// Always bound reads to this frame's payload (compressedLength bytes on the wire).
	// copyN relies on hitting EOF at the frame boundary to move on to the next
	// compressed packet.
	limitedReader := io.LimitReader(c.reader, int64(compressedLength))
	if uncompressedLength > 0 {
		switch c.Compression {
		case mysql.MYSQL_COMPRESS_ZLIB:
			return compress.GetPooledZlibReader(limitedReader)
		case mysql.MYSQL_COMPRESS_ZSTD:
			return zstd.NewReader(limitedReader)
		}
	}

	// uncompressedLength == 0 means the payload was sent verbatim (compression wasn't
	// worthwhile for this chunk). It must still be bounded to the frame: returning the
	// raw, unbounded connection here lets a packet that spans into the following frame
	// read straight through that frame's header, desyncing the compressed stream and
	// surfacing later as "invalid compressed sequence" / "zlib: invalid header".
	return limitedReader, nil
}

func (c *Conn) currentPacketReader() io.Reader {
	if c.Compression == mysql.MYSQL_COMPRESS_NONE || c.compressedReader == nil {
		return c.reader
	}
	return c.compressedReader
}

// acquireReadBudget reserves up to want bytes of shared read budget for data
// about to leave the wire. It is non-blocking: when the process-wide budget is
// exhausted, the connection is failed with ErrReadLimitExhausted instead of
// queueing, so a single hungry connection cannot stall the others. Acquired
// bytes stay reserved until released in releaseReadBudget (packet delivery or
// forced disconnect), which is what bounds memory to the shared limit.
func (c *Conn) acquireReadBudget(want int) (int, error) {
	limiter := c.readLimiterLocked()
	if limiter == nil {
		return want, nil
	}
	if limiter.tryAcquire(want) {
		c.reserved.Add(int64(want))
		return want, nil
	}
	return 0, newPacketError(ErrReadLimitExhausted,
		fmt.Sprintf("wanted %d more bytes, %d/%d in use", want, limiter.Used(), limiter.Limit()))
}

func (c *Conn) releaseReadBudget(n int) {
	if n <= 0 {
		return
	}
	if held := c.reserved.Add(-int64(n)); held < 0 {
		// failRead may have released the whole reservation already.
		c.reserved.Add(int64(n))
		return
	}
	if limiter := c.readLimiterLocked(); limiter != nil {
		limiter.release(n)
	}
}

// classifyReadTimeout turns a deadline error into the idle-vs-mid-packet
// distinction. A timeout with zero bytes of the current packet in hand means
// the peer never started sending (idle); any progress means it stalled halfway.
// Non-timeout errors are returned unchanged for the caller to wrap.
func (c *Conn) classifyReadTimeout(err error) error {
	if !isDeadlineExceeded(err) {
		return err
	}
	if c.stats.currentPacketBytes.Load() == 0 {
		c.stats.idleTimeouts.Add(1)
		return newPacketError(ErrReadIdleTimeout,
			fmt.Sprintf("after %s: %v", c.readTimeout, err))
	}
	c.stats.packetTimeouts.Add(1)
	return newPacketError(ErrReadPacketTimeout,
		fmt.Sprintf("after %s with %d bytes in flight: %v",
			c.readTimeout, c.stats.currentPacketBytes.Load(), err))
}

// isDeadlineExceeded recognizes net.OpError-wrapped timeout errors from both
// TCP and TLS transports.
func isDeadlineExceeded(err error) bool {
	var netErr net.Error
	return goErrors.As(err, &netErr) && netErr.Timeout()
}

// wrapBadConn annotates ordinary read failures as bad-connection errors while
// passing the typed read-protection errors (size/budget/timeouts) through
// untouched: those already implement ErrBadConn via Is, and re-wrapping them
// around a fresh ErrBadConn root would detach their sentinel from the chain.
func (c *Conn) wrapBadConn(err error, context string) error {
	if isReadProtectionError(err) {
		return err
	}
	return errors.Wrapf(mysql.ErrBadConn, "%s. err %v", context, err)
}

func isReadProtectionError(err error) bool {
	return goErrors.Is(err, ErrPacketTooLarge) ||
		goErrors.Is(err, ErrReadLimitExhausted) ||
		goErrors.Is(err, ErrReadIdleTimeout) ||
		goErrors.Is(err, ErrReadPacketTimeout)
}

func (c *Conn) copyN(dst io.Writer, n int64) (int64, error) {
	var written int64

	for n > 0 {
		bcap := cap(c.copyNBuf)
		if int64(bcap) > n {
			bcap = int(n)
		}
		buf := c.copyNBuf[:bcap]

		// Call ReadAtLeast with the currentPacketReader as it may change on every iteration
		// of this loop. A complete uncompressed chunk already in bufio cannot
		// block on the connection. Otherwise keep one deadline for the entire
		// ReadAtLeast, including partial reads; refreshing on every underlying
		// Read would let a slow peer extend the timeout indefinitely.
		needsNetwork := c.Compression != mysql.MYSQL_COMPRESS_NONE || c.br == nil || c.br.Buffered() < bcap
		if c.readTimeout != 0 && needsNetwork {
			if err := c.SetReadDeadline(utils.Now().Add(c.readTimeout)); err != nil {
				return written, err
			}
		}

		// Reserve shared budget before any byte can land in memory. Without a
		// limiter this is a no-op and bcap bytes are read as before.
		want, err := c.acquireReadBudget(bcap)
		if err != nil {
			return written, c.failRead(err)
		}
		rd, readErr := io.ReadAtLeast(c.currentPacketReader(), buf, want)
		// reads/partialReads are recorded in countingReader at each raw
		// transport Read; here we only track packet progress.
		c.stats.currentPacketBytes.Add(uint64(rd))

		n -= int64(rd)

		// ReadAtLeast will return EOF or ErrUnexpectedEOF when fewer than the min
		// bytes are read. In this case, and when we have compression then advance
		// the sequence number and reset the compressed reader to continue reading
		// the remaining bytes in the next compressed packet.
		if c.Compression != mysql.MYSQL_COMPRESS_NONE &&
			(goErrors.Is(readErr, io.ErrUnexpectedEOF) || goErrors.Is(readErr, io.EOF)) {
			// we have read to EOF and read an incomplete uncompressed packet
			// so reset the compressed reader to get the remaining unread
			// uncompressed bytes from the next compressed packet.
			if c.compressedReader, err = c.newCompressedPacketReader(); err != nil {
				c.releaseReadBudget(rd)
				return written, errors.Trace(err)
			}
			// The EOF only marked the frame boundary; the logical packet
			// continues from the fresh reader on the next iteration.
			readErr = nil
		}

		if readErr != nil {
			// On a timeout failRead releases the whole outstanding
			// reservation itself, so do not release here first (that would
			// double-count). Non-timeout errors do release this read's bytes.
			classified := c.classifyReadTimeout(errors.Trace(readErr))
			if goErrors.Is(classified, ErrReadIdleTimeout) || goErrors.Is(classified, ErrReadPacketTimeout) {
				// A timeout is a hard disconnect: release reservations and
				// buffered partial bytes, and mark the Conn so the packet
				// already in flight can never be delivered.
				return written, c.failRead(classified)
			}
			c.releaseReadBudget(rd)
			return written, errors.Trace(readErr)
		}

		// careful to only write from the buffer the number of bytes read
		wr, err := dst.Write(buf[:rd])
		written += int64(wr)
		if err != nil {
			c.releaseReadBudget(rd)
			return written, errors.Trace(err)
		}
		// Bytes now live in the destination (or have been delivered to the
		// caller): release their shared-budget reservation.
		c.releaseReadBudget(rd)
	}

	return written, nil
}

func (c *Conn) ReadPacketTo(w io.Writer) error {
	if err := c.checkReadable(); err != nil {
		return err
	}
	c.syncSequenceForRead()
	if c.Compression != mysql.MYSQL_COMPRESS_NONE {
		// Packets read back to back keep their own sequence; the switch to
		// the compressed sequence happens once, before the next write.
		c.syncWriteSequence = true
	}

	// The peer may be waiting on our buffered output before it sends more.
	if err := c.Flush(); err != nil {
		return err
	}

	b := utils.BytesBufferGet()
	defer func() {
		utils.BytesBufferPut(b)
	}()

	// packets that come in a compressed packet may be partial
	// so use the copyN function to read the packet header into a
	// buffer, since copyN is capable of getting the next compressed
	// packet and updating the Conn state with a new compressedReader.
	if _, err := c.copyN(b, 4); err != nil {
		return c.wrapBadConn(err, "io.ReadFull(header) failed")
	}
	// copy was successful so copy the 4 bytes from the buffer to the header
	copy(c.header[:4], b.Bytes()[:4])

	length := int(uint32(c.header[0]) | uint32(c.header[1])<<8 | uint32(c.header[2])<<16)
	sequence := c.header[3]

	if sequence != c.Sequence {
		// A mismatched sequence leaves the stream desynced beyond recovery, so the
		// connection is unusable: report it as bad, like the read failures above, so
		// callers discard it instead of retrying on it.
		return errors.Wrapf(mysql.ErrBadConn, "invalid sequence %d != %d", sequence, c.Sequence)
	}

	c.Sequence++

	// Enforce the per-connection cap before any payload byte is appended. The
	// check runs on the running total of the whole logical packet, so packets
	// split over continuation frames cannot bypass it frame by frame, and it
	// covers bytes already pulled into the read buffer: an oversized header
	// already sitting in bufio is rejected here instead of being read out.
	inFlight := c.stats.currentPacketBytes.Load()
	if maxSize := c.maxPacketSizeLocked(); maxSize > 0 && int(inFlight)+length > maxSize {
		c.stats.oversizedRejects.Add(1)
		return c.failRead(newPacketError(ErrPacketTooLarge,
			fmt.Sprintf("packet would be %d bytes (already buffered %d), limit is %d from %s",
				int(inFlight)+length, inFlight, maxSize, c.remoteAddrString())))
	}
	c.stats.currentPacketExpect.Store(inFlight + uint64(length))

	if buf, ok := w.(*bytes.Buffer); ok {
		// Allocate the buffer with expected length directly instead of call `grow` and migrate data many times.
		buf.Grow(length)
	}

	if n, err := c.copyN(w, int64(length)); err != nil {
		if isReadProtectionError(err) {
			return err
		}
		return errors.Wrapf(mysql.ErrBadConn, "io.CopyN failed. err %v, copied %v, expected %v", err, n, length)
	} else if n != int64(length) {
		return errors.Wrapf(mysql.ErrBadConn, "io.CopyN failed(n != int64(length)). %v bytes copied, while %v expected", n, length)
	}
	if length < mysql.MaxPayloadLen {
		// A full logical packet has been delivered: clear per-packet progress.
		c.stats.currentPacketBytes.Store(0)
		c.stats.currentPacketExpect.Store(0)
		return nil
	}

	// A max-length frame carries a continuation frame. The cap check above
	// runs again on the accumulated size, so the threshold applies to the
	// whole packet rather than to each frame independently.
	if err := c.ReadPacketTo(w); err != nil {
		return errors.Wrap(err, "ReadPacketTo failed")
	}

	return nil
}

// WritePacket data already has 4 bytes header will modify data in-place
func (c *Conn) WritePacket(data []byte) error {
	c.syncSequenceForWrite()

	length := len(data) - 4

	for length >= mysql.MaxPayloadLen {
		data[0] = 0xff
		data[1] = 0xff
		data[2] = 0xff

		data[3] = c.Sequence

		if n, err := c.writePacketData(data[:4+mysql.MaxPayloadLen]); err != nil {
			return errors.Wrapf(mysql.ErrBadConn,
				"Write(payload portion) failed. err %v", err)
		} else if n != (4 + mysql.MaxPayloadLen) {
			return errors.Wrapf(mysql.ErrBadConn,
				"Write(payload portion) failed. only %v bytes written, while %v expected", n, 4+mysql.MaxPayloadLen)
		}
		c.Sequence++
		length -= mysql.MaxPayloadLen
		data = data[mysql.MaxPayloadLen:]
	}

	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = c.Sequence

	switch c.Compression {
	case mysql.MYSQL_COMPRESS_NONE:
		if n, err := c.writeWithTimeout(data); err != nil {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. err %v", err)
		} else if n != len(data) {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. only %v bytes written, while %v expected", n, len(data))
		}
	case mysql.MYSQL_COMPRESS_ZLIB, mysql.MYSQL_COMPRESS_ZSTD:
		if n, err := c.writeCompressed(data); err != nil {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. err %v", err)
		} else if n != len(data) {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. only %v bytes written, while %v expected", n, len(data))
		}

		if c.compressedReader != nil {
			if _, ok := c.compressedReader.(io.ReadCloser); ok {
				_ = c.compressedReader.(io.ReadCloser).Close()
			}
			c.compressedReader = nil
		}
	default:
		return errors.Wrapf(mysql.ErrBadConn, "Write failed. Unsuppored compression algorithm set")
	}

	c.Sequence++
	if c.Compression != mysql.MYSQL_COMPRESS_NONE {
		// Packets written back to back keep their own sequence; the switch to
		// the compressed sequence happens once, before the next read.
		c.syncSequence = true
	}
	return nil
}

// syncSequenceForRead runs at the write-to-read boundary. With compression,
// the peer continues the packet sequence from the compressed sequence once it
// has read our packets (net_flush in MySQL's sql-common/net_serv.cc does the
// same on its side). The two only differ when a packet was split over several
// compressed packets. go-sql-driver/mysql's syncSequence does the same.
func (c *Conn) syncSequenceForRead() {
	if c.syncSequence {
		c.Sequence = c.CompressedSequence
		c.syncSequence = false
	}
}

// syncSequenceForWrite runs at the read-to-write boundary, the mirror of
// syncSequenceForRead: once the peer has flushed the compressed packets we
// just read, it expects our next packet to continue from the compressed
// sequence. The two differ when a packet read was split over several
// compressed packets, e.g. an incompressible packet of 16MB or more.
func (c *Conn) syncSequenceForWrite() {
	if c.syncWriteSequence {
		c.Sequence = c.CompressedSequence
		c.syncWriteSequence = false
	}
}

// writePacketData writes b, which holds one or more complete packets, either
// as is or wrapped in compressed packets.
func (c *Conn) writePacketData(b []byte) (int, error) {
	switch c.Compression {
	case mysql.MYSQL_COMPRESS_NONE:
		return c.writeWithTimeout(b)
	case mysql.MYSQL_COMPRESS_ZLIB, mysql.MYSQL_COMPRESS_ZSTD:
		return c.writeCompressed(b)
	default:
		return 0, errors.Wrapf(mysql.ErrBadConn, "Write failed. Unsuppored compression algorithm set")
	}
}

func (c *Conn) writeWithTimeout(b []byte) (n int, err error) {
	if c.bw != nil {
		return c.bw.Write(b)
	}
	return c.writeDirect(b)
}

func (c *Conn) writeDirect(b []byte) (n int, err error) {
	if c.writeTimeout != 0 {
		if err := c.SetWriteDeadline(utils.Now().Add(c.writeTimeout)); err != nil {
			return n, err
		}
	}

	return c.Write(b)
}

// writeCompressed sends data in compressed packets. A compressed packet can
// carry at most mysql.MaxPayloadLen bytes, so larger data, such as a packet
// of 16MB or more, is split over several of them.
func (c *Conn) writeCompressed(data []byte) (n int, err error) {
	for len(data) > 0 {
		chunk := data
		if len(chunk) > mysql.MaxPayloadLen {
			chunk = chunk[:mysql.MaxPayloadLen]
		}
		if err = c.writeCompressedPacket(chunk); err != nil {
			return n, err
		}
		n += len(chunk)
		data = data[len(chunk):]
	}
	return n, nil
}

// writeCompressedPacket sends data, at most mysql.MaxPayloadLen bytes, as a
// single compressed packet.
func (c *Conn) writeCompressedPacket(data []byte) (err error) {
	var (
		compressedLength, uncompressedLength int
		payload                              *bytes.Buffer
		compressedHeader                     [7]byte
	)

	if len(data) > MinCompressionLength {
		var w io.WriteCloser
		payload = utils.BytesBufferGet()
		defer utils.BytesBufferPut(payload)

		switch c.Compression {
		case mysql.MYSQL_COMPRESS_ZLIB:
			w, err = compress.GetPooledZlibWriter(payload)
		case mysql.MYSQL_COMPRESS_ZSTD:
			w, err = zstd.NewWriter(payload)
		default:
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. Unsuppored compression algorithm set")
		}
		if err != nil {
			return err
		}

		if _, err = w.Write(data); err != nil {
			_ = w.Close()
			return err
		}
		if err = w.Close(); err != nil {
			return err
		}

		if payload.Len() < len(data) {
			uncompressedLength = len(data)
			compressedLength = payload.Len()
		} else {
			// Compression did not help, and the compressed length might not
			// even fit in the header: send the data uncompressed.
			payload = nil
		}
	}
	if payload == nil {
		compressedLength = len(data)
	}

	// write the compressed packet header
	compressedPacket := utils.BytesBufferGet()
	defer utils.BytesBufferPut(compressedPacket)

	compressedHeader[0] = byte(compressedLength)
	compressedHeader[1] = byte(compressedLength >> 8)
	compressedHeader[2] = byte(compressedLength >> 16)
	compressedHeader[3] = c.CompressedSequence
	compressedHeader[4] = byte(uncompressedLength)
	compressedHeader[5] = byte(uncompressedLength >> 8)
	compressedHeader[6] = byte(uncompressedLength >> 16)
	if _, err = compressedPacket.Write(compressedHeader[:]); err != nil {
		return err
	}
	c.CompressedSequence++

	if payload != nil {
		_, err = compressedPacket.Write(payload.Bytes())
	} else {
		_, err = compressedPacket.Write(data)
	}
	if err != nil {
		return err
	}
	_, err = c.writeWithTimeout(compressedPacket.Bytes())
	return err
}

// WriteClearAuthPacket Client clear text authentication packet
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
func (c *Conn) WriteClearAuthPacket(password string) error {
	// Calculate the packet length and add a tailing 0
	pktLen := len(password) + 1
	data := make([]byte, 4+pktLen)

	// Add the clear password [null terminated string]
	copy(data[4:], password)
	data[4+pktLen-1] = 0x00

	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

// WritePublicKeyAuthPacket Caching sha2 authentication. Public key request and send encrypted password
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
func (c *Conn) WritePublicKeyAuthPacket(password string, cipher []byte) error {
	// request public key
	data := make([]byte, 4+1)
	data[4] = 2 // cachingSha2PasswordRequestPublicKey
	if err := c.WritePacket(data); err != nil {
		return errors.Wrap(err, "WritePacket(single byte) failed")
	}

	data, err := c.ReadPacket()
	if err != nil {
		return errors.Wrap(err, "ReadPacket failed")
	}

	block, _ := pem.Decode(data[1:])
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "x509.ParsePKIXPublicKey failed")
	}

	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(cipher)
		plain[i] ^= cipher[j]
	}
	sha1v := sha1.New()
	enc, _ := rsa.EncryptOAEP(sha1v, rand.Reader, pub.(*rsa.PublicKey), plain, nil)
	data = make([]byte, 4+len(enc))
	copy(data[4:], enc)
	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

func (c *Conn) WriteEncryptedPassword(password string, seed []byte, pub *rsa.PublicKey) error {
	enc, err := mysql.EncryptPassword(password, seed, pub)
	if err != nil {
		return errors.Wrap(err, "EncryptPassword failed")
	}
	return errors.Wrap(c.WriteAuthSwitchPacket(enc, false), "WriteAuthSwitchPacket failed")
}

// WriteAuthSwitchPacket see https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
func (c *Conn) WriteAuthSwitchPacket(authData []byte, addNUL bool) error {
	pktLen := 4 + len(authData)
	if addNUL {
		pktLen++
	}
	data := make([]byte, pktLen)

	// Add the auth data [EOF]
	copy(data[4:], authData)
	if addNUL {
		data[pktLen-1] = 0x00
	}

	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

func (c *Conn) ResetSequence() {
	c.Sequence = 0
	c.CompressedSequence = 0
	c.syncSequence = false
	c.syncWriteSequence = false
}

func (c *Conn) Close() error {
	c.Sequence = 0
	// Mark the connection closed and hand back any shared budget so other
	// connections can use it immediately. failRead may already have run, in
	// which case these are no-ops.
	c.limitCfg.mu.Lock()
	c.limitCfg.closed = true
	c.limitCfg.mu.Unlock()
	if held := c.reserved.Swap(0); held > 0 {
		if limiter := c.readLimiterLocked(); limiter != nil {
			limiter.release(int(held))
		}
	}
	c.stats.currentPacketBytes.Store(0)
	c.stats.currentPacketExpect.Store(0)
	if c.Conn != nil {
		return errors.Wrap(c.Conn.Close(), "Conn.Close failed")
	}
	return nil
}
