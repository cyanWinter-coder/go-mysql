package server

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
)

// userConfigurableServerCapabilities lists handshake flags that may be toggled
// via SetCapability / UnsetCapability. Other flags (e.g. CLIENT_SSL) are derived
// from server construction and must not be changed independently.
const userConfigurableServerCapabilities = mysql.CLIENT_FOUND_ROWS |
	mysql.CLIENT_LOCAL_FILES |
	mysql.CLIENT_MULTI_RESULTS |
	mysql.CLIENT_PS_MULTI_RESULTS |
	mysql.CLIENT_DEPRECATE_EOF

// Defines a basic MySQL server with configs.
//
// We do not aim at implementing the whole MySQL connection suite to have the best compatibilities for the clients.
// The MySQL server can be configured to switch auth methods covering 'mysql_old_password', 'mysql_native_password',
// 'mysql_clear_password', 'authentication_windows_client', 'sha256_password', 'caching_sha2_password', etc.
//
// However, since some old auth methods are considered broken with security issues. MySQL major versions like 5.7 and 8.0 default to
// 'mysql_native_password' or 'caching_sha2_password', and most MySQL clients should have already supported at least one of the three auth
// methods 'mysql_native_password', 'caching_sha2_password', and 'sha256_password'. Thus here we will only support these three
// auth methods, and use 'mysql_native_password' as default for maximum compatibility with the clients and leave the other two as
// config options.
//
// The MySQL doc states that 'mysql_old_password' will be used if 'CLIENT_PROTOCOL_41' or 'CLIENT_SECURE_CONNECTION' flag is not set.
// We choose to drop the support for insecure 'mysql_old_password' auth method and require client capability 'CLIENT_PROTOCOL_41' and 'CLIENT_SECURE_CONNECTION'
// are set. Besides, if 'CLIENT_PLUGIN_AUTH' is not set, we fallback to 'mysql_native_password' auth method.
type Server struct {
	serverVersion     string // e.g. "8.0.12"
	protocolVersion   int    // minimal 10
	capability        uint32 // server capability flag
	collationID       uint8
	defaultAuthMethod string // default authentication method, 'mysql_native_password'
	rsaPrivateKey     *rsa.PrivateKey
	rsaPublicKeyBytes []byte
	tlsConfig         *tls.Config
	cacheShaPassword  *sync.Map // 'user@host' -> SHA256(SHA256(PASSWORD))
	authProvider      AuthenticationProvider
	initialStatus     atomic.Uint32 // SERVER_STATUS_* flags of a new connection (see SetInitialStatus)
	cursorsDisabled   atomic.Bool   // see SetCursorsEnabled

	// Read protection applied to every new connection. See packet.Conn.
	maxPacketSize atomic.Int64 // 0 = unlimited; packets larger than this disconnect the client
	readLimiter   *packet.ReadLimiter
}

// NewDefaultServer: New mysql server with default settings.
//
// NOTES:
// TLS support will be enabled by default with auto-generated CA and server certificates (however, you can still use
// non-TLS connection). By default, it will verify the client certificate if present. You can enable TLS support on
// the client side without providing a client-side certificate. So only when you need the server to verify client
// identity for maximum security, you need to set a signed certificate for the client.
func NewDefaultServer() *Server {
	caPem, caKey := generateCA()
	certPem, keyPem := generateAndSignRSACerts(caPem, caKey)
	tlsConf := NewServerTLSConfig(caPem, certPem, keyPem, tls.VerifyClientCertIfGiven)
	rsaPrivateKey, rsaPublicKeyBytes := getRSAKeyPairFromPEM(keyPem)
	return &Server{
		serverVersion:   "8.0.11",
		protocolVersion: 10,
		capability: mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG | mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 |
			mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_SSL |
			mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | mysql.CLIENT_CONNECT_ATTRS | mysql.CLIENT_SESSION_TRACK |
			mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS | mysql.CLIENT_DEPRECATE_EOF,
		collationID:       mysql.DEFAULT_COLLATION_ID,
		defaultAuthMethod: mysql.AUTH_NATIVE_PASSWORD,
		rsaPrivateKey:     rsaPrivateKey,
		rsaPublicKeyBytes: rsaPublicKeyBytes,
		tlsConfig:         tlsConf,
		cacheShaPassword:  new(sync.Map),
		authProvider:      &DefaultAuthenticationProvider{},
	}
}

// NewServer: New mysql server with customized settings.
//
// NOTES:
// You can control the authentication methods and TLS settings here.
//
// For auth method, you can specify one of the supported methods 'mysql_native_password', 'caching_sha2_password', and 'sha256_password'.
// The specified auth method will be enforced by the server in the connection phase. That means, client will be asked to switch auth method
// if the supplied auth method is different from the server default.
//
// For TLS support, you can specify self-signed or CA-signed certificates and decide whether the client needs to provide
// a signed or unsigned certificate to provide different level of security.
//
// The rsaKey parameter is used for password encryption on non-TLS connections with 'caching_sha2_password' and 'sha256_password'.
// If it's is nil, it will attempt to extract an RSA key from tlsConfig.Certificates[0].
// If no RSA key is available, non-TLS connections will not be supported for these auth methods (TLS connections will still work).
func NewServer(serverVersion string, collationID uint8, defaultAuthMethod string, rsaKey *rsa.PrivateKey, tlsConfig *tls.Config) *Server {
	authProvider := &DefaultAuthenticationProvider{}
	return NewServerWithAuth(serverVersion, collationID, defaultAuthMethod, rsaKey, tlsConfig, authProvider)
}

func NewServerWithAuth(serverVersion string, collationID uint8, defaultAuthMethod string, rsaKey *rsa.PrivateKey, tlsConfig *tls.Config, authProvider AuthenticationProvider) *Server {
	if authProvider == nil || !authProvider.Validate(defaultAuthMethod) {
		panic(fmt.Sprintf("server authentication method '%s' is not supported", defaultAuthMethod))
	}

	if rsaKey == nil && (defaultAuthMethod == mysql.AUTH_CACHING_SHA2_PASSWORD || defaultAuthMethod == mysql.AUTH_SHA256_PASSWORD) {
		if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
			rsaKey, _ = tlsConfig.Certificates[0].PrivateKey.(*rsa.PrivateKey)
		} else {
			panic("either rsaKey or tlsConfig is required for caching_sha2_password and sha256_password authentication")
		}
	}

	capFlag := mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG | mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 |
		mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_CONNECT_ATTRS |
		mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | mysql.CLIENT_SESSION_TRACK |
		mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS | mysql.CLIENT_DEPRECATE_EOF
	if tlsConfig != nil {
		capFlag |= mysql.CLIENT_SSL
	}
	return &Server{
		serverVersion:     serverVersion,
		protocolVersion:   10,
		capability:        capFlag,
		collationID:       collationID,
		defaultAuthMethod: defaultAuthMethod,
		rsaPrivateKey:     rsaKey,
		rsaPublicKeyBytes: rsaPublicKeyBytes(rsaKey),
		tlsConfig:         tlsConfig,
		cacheShaPassword:  new(sync.Map),
		authProvider:      authProvider,
	}
}

func isAuthMethodSupported(authMethod string) bool {
	return authMethod == mysql.AUTH_NATIVE_PASSWORD || authMethod == mysql.AUTH_CACHING_SHA2_PASSWORD || authMethod == mysql.AUTH_SHA256_PASSWORD || authMethod == mysql.AUTH_CLEAR_PASSWORD
}

// userConfigurableInitialStatus are the SERVER_STATUS_* flags SetInitialStatus
// accepts: the ones that describe a session's state before it runs anything.
const userConfigurableInitialStatus = mysql.SERVER_STATUS_AUTOCOMMIT | mysql.SERVER_STATUS_NO_BACKSLASH_ESCAPED

// SetInitialStatus sets the SERVER_STATUS_* flags a new connection starts with
// (default: none). Set them here rather than on the Conn: the handshake and the
// auth OK are sent before NewCustomizedConn returns. MySQL starts sessions with
// SERVER_STATUS_AUTOCOMMIT. Only SERVER_STATUS_AUTOCOMMIT and
// SERVER_STATUS_NO_BACKSLASH_ESCAPED are accepted. Applies to new connections.
func (s *Server) SetInitialStatus(status uint16) error {
	if invalid := status &^ userConfigurableInitialStatus; invalid != 0 {
		return fmt.Errorf("initial status %#x contains flags %#x that do not describe a new session; only SERVER_STATUS_AUTOCOMMIT and SERVER_STATUS_NO_BACKSLASH_ESCAPED are supported", status, invalid)
	}
	s.initialStatus.Store(uint32(status))
	return nil
}

// InitialStatus returns the SERVER_STATUS_* flags a new connection starts with
// (see SetInitialStatus).
func (s *Server) InitialStatus() uint16 {
	return uint16(s.initialStatus.Load())
}

// SetCursorsEnabled sets whether CURSOR_TYPE_READ_ONLY opens a cursor (default:
// enabled). A cursor holds its whole Resultset until it is fetched, so a Handler
// that limits result memory per command should disable cursors. When disabled,
// the rows are sent inline without SERVER_STATUS_CURSOR_EXISTS, as MySQL does
// when it opens no cursor. It applies to executions that start after the call.
func (s *Server) SetCursorsEnabled(enabled bool) {
	s.cursorsDisabled.Store(!enabled)
}

// CursorsEnabled reports whether cursors are enabled (see SetCursorsEnabled).
func (s *Server) CursorsEnabled() bool {
	return !s.cursorsDisabled.Load()
}

func (s *Server) InvalidateCache(username string, host string) {
	s.cacheShaPassword.Delete(fmt.Sprintf("%s@%s", username, host))
}

// SetMaxPacketSize caps the total payload size of any packet a client may
// send on connections accepted afterwards. The cap applies to the whole
// logical packet, including continuation frames and data already buffered in
// memory; an oversized packet disconnects only that one connection with a
// packet.ErrPacketTooLarge error. A non-positive value (the default) removes
// the cap, so legitimate large result sets continue to work until an
// explicit threshold is configured.
func (s *Server) SetMaxPacketSize(maxBytes int) {
	s.maxPacketSize.Store(int64(maxBytes))
}

// MaxPacketSize returns the per-connection packet cap, or 0 when unlimited.
func (s *Server) MaxPacketSize() int {
	return int(s.maxPacketSize.Load())
}

// SetReadLimiter shares a process-wide read-memory budget across all new
// connections. Budget is only held for bytes pulled from the wire but not yet
// delivered, so a single client can reserve at most its own packet and cannot
// starve the others; a client that cannot acquire budget is disconnected with
// packet.ErrReadLimitExhausted while the rest keep working. Pass nil to
// detach.
func (s *Server) SetReadLimiter(l *packet.ReadLimiter) {
	s.readLimiter = l
}

// ReadLimiter returns the shared budget applied to new connections, or nil.
func (s *Server) ReadLimiter() *packet.ReadLimiter {
	return s.readLimiter
}

// Capability returns the capability flags advertised in the initial handshake.
func (s *Server) Capability() uint32 {
	return atomic.LoadUint32(&s.capability)
}

// SetCapability enables additional server capabilities advertised in the handshake.
// Only CLIENT_FOUND_ROWS, CLIENT_LOCAL_FILES, CLIENT_MULTI_RESULTS,
// CLIENT_PS_MULTI_RESULTS, and CLIENT_DEPRECATE_EOF may be set; other flags are
// managed by server construction (e.g. CLIENT_SSL requires TLS).
//
// Advertising a capability does not implement it. CLIENT_FOUND_ROWS, which makes an
// UPDATE report rows matched instead of rows changed, is up to the Handler: this
// package never computes affected rows. A Handler honoring it must check
// (*Conn).HasCapability(mysql.CLIENT_FOUND_ROWS) and set AffectedRows on the
// mysql.Result it returns accordingly.
func (s *Server) SetCapability(capability uint32) error {
	if err := validateUserConfigurableCapability(capability); err != nil {
		return err
	}
	for {
		old := atomic.LoadUint32(&s.capability)
		if atomic.CompareAndSwapUint32(&s.capability, old, old|capability) {
			break
		}
	}
	return nil
}

// UnsetCapability disables server capabilities advertised in the handshake.
// Only CLIENT_FOUND_ROWS, CLIENT_LOCAL_FILES, CLIENT_MULTI_RESULTS,
// CLIENT_PS_MULTI_RESULTS, and CLIENT_DEPRECATE_EOF may be cleared via this API.
func (s *Server) UnsetCapability(capability uint32) error {
	if err := validateUserConfigurableCapability(capability); err != nil {
		return err
	}
	for {
		old := atomic.LoadUint32(&s.capability)
		if atomic.CompareAndSwapUint32(&s.capability, old, old&^capability) {
			break
		}
	}
	return nil
}

func validateUserConfigurableCapability(capability uint32) error {
	if capability == 0 {
		return fmt.Errorf("capability must not be zero")
	}
	if invalid := capability &^ userConfigurableServerCapabilities; invalid != 0 {
		return fmt.Errorf("server capability %#x contains non-user-configurable flags %#x; only CLIENT_FOUND_ROWS, CLIENT_LOCAL_FILES, CLIENT_MULTI_RESULTS, CLIENT_PS_MULTI_RESULTS, and CLIENT_DEPRECATE_EOF are supported", capability, invalid)
	}
	return nil
}
