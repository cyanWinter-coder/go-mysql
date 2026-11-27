package client

import (
	"errors"
	"log/slog"

	"github.com/go-mysql-org/go-mysql/packet"
)

// errInvalidMaxPacketSize is returned by WithMaxPacketSize for a negative
// limit (use 0 explicitly to mean unlimited).
var errInvalidMaxPacketSize = errors.New("MaxPacketSize must not be negative; use 0 for unlimited")

// applyReadProtection pushes the client's read-protection settings onto the
// underlying packet connection. It runs whenever the packet.Conn is created
// or replaced (initial connect and TLS upgrade).
func (c *Conn) applyReadProtection() {
	if c.MaxPacketSize > 0 {
		c.Conn.SetMaxPacketSize(c.MaxPacketSize)
	}
	if c.ReadLimiter != nil {
		c.Conn.SetReadLimiter(c.ReadLimiter)
	}
	if c.readLogger != nil {
		c.Conn.SetReadLogger(c.readLogger)
	}
}

// WithMaxPacketSize caps the payload size of any packet read from the server
// on this connection. The cap covers the whole logical packet (continuation
// frames included) and data already buffered; 0 leaves the size unlimited so
// legitimate large result sets keep working unless a threshold is set. An
// oversized response closes the connection with packet.ErrPacketTooLarge.
func WithMaxPacketSize(maxBytes int) Option {
	return func(c *Conn) error {
		if maxBytes < 0 {
			return errInvalidMaxPacketSize
		}
		c.MaxPacketSize = maxBytes
		return nil
	}
}

// WithReadLimiter attaches a process-wide shared read budget. A connection
// only holds budget for bytes in flight, so one connection can never
// monopolize it; a connection that cannot acquire budget is disconnected with
// packet.ErrReadLimitExhausted.
func WithReadLimiter(l *packet.ReadLimiter) Option {
	return func(c *Conn) error {
		c.ReadLimiter = l
		return nil
	}
}

// WithReadLogger records forced disconnects (oversize, exhausted shared
// budget, idle/mid-packet timeouts) with the reason, bytes already read and
// peer address, so malicious packets can be told apart from large result sets.
func WithReadLogger(logger *slog.Logger) Option {
	return func(c *Conn) error {
		c.readLogger = logger
		return nil
	}
}
