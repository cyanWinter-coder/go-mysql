package server

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
)

// Conn acts like a MySQL server connection, you can use MySQL client to communicate with it.
type Conn struct {
	*packet.Conn

	serverConf     *Server
	capability     uint32
	charset        uint8
	collationID    uint16
	authPluginName string
	attributes     map[string]string
	connectionID   uint32
	status         uint16
	warnings       uint16
	salt           []byte // should be 8 + 12 for auth-plugin-data-part-1 and auth-plugin-data-part-2

	authHandler         AuthenticationHandler
	user                string
	credential          Credential
	cachingSha2FullAuth bool

	h Handler

	stmts  map[uint32]*Stmt
	stmtID uint32

	closed atomic.Bool
}

var (
	baseConnID    uint32 = 10000
	defaultServer        = sync.OnceValue(func() *Server {
		return NewDefaultServer()
	})
)

// NewConn: create connection with default server settings
//
// Deprecated: Use [Server.NewConn] instead.
func NewConn(conn net.Conn, user string, password string, h Handler) (*Conn, error) {
	return defaultServer().NewConn(conn, user, password, h)
}

// NewCustomizedConn: create connection with customized server settings
//
// Deprecated: Use [Server.NewCustomizedConn] instead.
func NewCustomizedConn(conn net.Conn, serverConf *Server, authHandler AuthenticationHandler, h Handler) (*Conn, error) {
	return serverConf.NewCustomizedConn(conn, authHandler, h)
}

// NewConn: create connection with default server settings
func (s *Server) NewConn(conn net.Conn, user string, password string, h Handler) (*Conn, error) {
	authHandler := NewInMemoryAuthenticationHandler()
	if err := authHandler.AddUser(user, password); err != nil {
		return nil, err
	}

	return s.NewCustomizedConn(conn, authHandler, h)
}

func (s *Server) NewCustomizedConn(conn net.Conn, authHandler AuthenticationHandler, h Handler) (*Conn, error) {
	var packetConn *packet.Conn
	if s.tlsConfig != nil {
		packetConn = packet.NewTLSConn(conn)
	} else {
		packetConn = packet.NewConn(conn)
	}

	c := &Conn{
		Conn:         packetConn,
		serverConf:   s,
		authHandler:  authHandler,
		h:            h,
		connectionID: atomic.AddUint32(&baseConnID, 1),
		status:       s.InitialStatus(),
		stmts:        make(map[uint32]*Stmt),
		salt:         mysql.RandomBuf(20),
	}
	c.closed.Store(false)

	if err := c.handshake(); err != nil {
		c.Close()
		return nil, err
	}

	// The handshake settled the final transport (the client may have upgraded
	// to TLS), so reads can be buffered from here on.
	c.EnableReadBuffering(packet.DefaultReadBufferSize)

	// Batch response packets into one write(2) per response. HandleCommand
	// flushes at each response boundary; streaming paths flush per event/row.
	c.EnableWriteBuffering(packet.DefaultBufferSize)

	return c, nil
}

// handshake runs the connection-phase negotiation in protocol order:
// server greeting, then the client's handshake response (capability
// negotiation, optional TLS upgrade, authentication). A failure in any
// phase aborts the handshake: later phases are not attempted, the caller
// closes the connection, and the returned *mysql.HandshakeError carries
// the failed phase, the peer address, and the per-phase timings collected
// up to the failure.
func (c *Conn) handshake() error {
	timings := mysql.NewHandshakeTimings()

	start := time.Now()
	if err := c.writeInitialHandshake(); err != nil {
		timings.Record(mysql.HandshakePhaseGreeting, time.Since(start))
		return c.failHandshake(mysql.HandshakePhaseGreeting, nil, timings, err)
	}
	timings.Record(mysql.HandshakePhaseGreeting, time.Since(start))

	start = time.Now()
	if err := c.readHandshakeResponse(); err != nil {
		timings.Record(mysql.HandshakePhaseAuth, time.Since(start))
		kind := handshakeFailureKind(err)
		err = c.accessDeniedError(err)
		c.authHandler.OnAuthFailure(c, err)
		// Report the failure to the client only when the transport is still
		// intact: after a failed TLS upgrade the peer expects a TLS stream,
		// so plaintext error bytes must not be written, and the remaining
		// bytes must not be parsed as plaintext either.
		if !errors.Is(err, mysql.ErrHandshakeTLS) {
			_ = c.writeError(err)
		}
		return c.failHandshake(handshakeFailurePhase(kind), kind, timings, err)
	}
	timings.Record(mysql.HandshakePhaseAuth, time.Since(start))

	if err := c.authHandler.OnAuthSuccess(c); err != nil {
		_ = c.writeError(err)
		return c.failHandshake(mysql.HandshakePhaseAuth, nil, timings, err)
	}

	if err := c.writeOK(nil); err != nil {
		return c.failHandshake(mysql.HandshakePhaseAuth, nil, timings, err)
	}

	c.ResetSequence()

	return nil
}

// handshakeFailureKind maps err to one of the stable mysql.ErrHandshake*
// identifiers, or returns nil if the failure has no stable classification
// (e.g. a malformed handshake packet). It must be called before
// accessDeniedError, which converts ErrAccessDenied into a MyError.
func handshakeFailureKind(err error) error {
	switch {
	case errors.Is(err, mysql.ErrHandshakeTLS):
		return mysql.ErrHandshakeTLS
	case errors.Is(err, mysql.ErrHandshakeCapabilityMismatch):
		return mysql.ErrHandshakeCapabilityMismatch
	case errors.Is(err, ErrAccessDenied):
		return mysql.ErrHandshakeAuth
	}
	return nil
}

// handshakeFailurePhase derives the failed negotiation phase from the
// failure classification; unclassified failures of the handshake response
// are reported in the auth phase, where they are detected.
func handshakeFailurePhase(kind error) mysql.HandshakePhase {
	switch kind {
	case mysql.ErrHandshakeTLS:
		return mysql.HandshakePhaseTLS
	case mysql.ErrHandshakeCapabilityMismatch:
		return mysql.HandshakePhaseCapability
	default:
		return mysql.HandshakePhaseAuth
	}
}

// failHandshake reports err as a *mysql.HandshakeError carrying the peer
// address and the per-phase timings collected up to the failure.
func (c *Conn) failHandshake(phase mysql.HandshakePhase, kind error, timings *mysql.HandshakeTimings, err error) error {
	remote := ""
	if addr := c.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	return &mysql.HandshakeError{
		Phase:      phase,
		Kind:       kind,
		RemoteAddr: remote,
		Timings:    timings,
		Err:        err,
	}
}

// accessDeniedError turns ErrAccessDenied into the ER_ACCESS_DENIED_ERROR a
// client is sent; other errors are returned unchanged.
func (c *Conn) accessDeniedError(err error) error {
	if !errors.Is(err, ErrAccessDenied) {
		return err
	}
	var usingPasswd uint16 = mysql.ER_YES
	if errors.Is(err, ErrAccessDeniedNoPassword) {
		usingPasswd = mysql.ER_NO
	}
	return mysql.NewDefaultError(mysql.ER_ACCESS_DENIED_ERROR, c.user,
		c.RemoteAddr().String(), mysql.MySQLErrName[usingPasswd])
}

func (c *Conn) Close() {
	c.closed.Store(true)
	c.Conn.Close()
}

func (c *Conn) Closed() bool {
	return c.closed.Load()
}

func (c *Conn) GetUser() string {
	return c.user
}

func (c *Conn) Capability() uint32 {
	return c.capability
}

func (c *Conn) SetCapability(capability uint32) {
	c.capability |= capability
}

func (c *Conn) UnsetCapability(capability uint32) {
	c.capability &= ^capability
}

func (c *Conn) HasCapability(capability uint32) bool {
	return c.capability&capability > 0
}

// deprecateEOF reports whether both sides negotiated CLIENT_DEPRECATE_EOF:
// resultsets are then OK-terminated (with an EOF 0xFE header) and the EOF
// separator after the column definitions is omitted.
func (c *Conn) deprecateEOF() bool {
	return c.capability&mysql.CLIENT_DEPRECATE_EOF > 0 &&
		c.serverConf.Capability()&mysql.CLIENT_DEPRECATE_EOF > 0
}

// Charset returns the low byte of the client's collation ID. The handshake
// carries only that byte, but COM_CHANGE_USER carries all 16 bits; see
// CollationID.
func (c *Conn) Charset() uint8 {
	return c.charset
}

// CollationID returns the client's collation ID: from the handshake (8 bits),
// or from the last COM_CHANGE_USER that named one (16 bits).
func (c *Conn) CollationID() uint16 {
	return c.collationID
}

// Attributes returns the connection attributes.
// Note that this is only sent to the server if CLIENT_CONNECT_ATTRS is set.
func (c *Conn) Attributes() map[string]string {
	return c.attributes
}

func (c *Conn) ConnectionID() uint32 {
	return c.connectionID
}

func (c *Conn) IsAutoCommit() bool {
	return c.HasStatus(mysql.SERVER_STATUS_AUTOCOMMIT)
}

func (c *Conn) IsInTransaction() bool {
	return c.HasStatus(mysql.SERVER_STATUS_IN_TRANS)
}

func (c *Conn) SetInTransaction() {
	c.SetStatus(mysql.SERVER_STATUS_IN_TRANS)
}

func (c *Conn) ClearInTransaction() {
	c.UnsetStatus(mysql.SERVER_STATUS_IN_TRANS)
}

func (c *Conn) SetStatus(status uint16) {
	c.status |= status
}

func (c *Conn) UnsetStatus(status uint16) {
	c.status &= ^status
}

func (c *Conn) HasStatus(status uint16) bool {
	return c.status&status > 0
}

func (c *Conn) SetWarnings(warnings uint16) {
	c.warnings = warnings
}
