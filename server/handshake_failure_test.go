package server

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/test_util/test_keys"
)

// runFailingServer accepts one connection and runs the handshake on it,
// returning the address and a channel reporting the handshake error.
func runFailingServer(t *testing.T, s *Server, authHandler AuthenticationHandler) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		serverConn, err := s.NewCustomizedConn(conn, authHandler, &EmptyHandler{})
		if serverConn != nil {
			serverConn.Close()
		}
		done <- err
	}()
	return l.Addr().String(), done
}

func readClientPacket(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 4)
	_, err := io.ReadFull(conn, hdr)
	require.NoError(t, err)
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, length)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)
	return payload
}

// handshakeResponse builds a minimal HandshakeResponse41 payload.
func handshakeResponse(capability uint32, user string) []byte {
	payload := make([]byte, 0, 64)
	payload = binary.LittleEndian.AppendUint32(payload, capability)
	payload = append(payload, 0, 0, 0, 0) // max packet size
	payload = append(payload, 45)         // charset
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, user...)
	payload = append(payload, 0x00)
	payload = append(payload, 0x00) // empty auth response (CLIENT_SECURE_CONNECTION)
	return payload
}

func writeClientPacket(t *testing.T, conn net.Conn, seq byte, payload []byte) {
	t.Helper()
	pkt := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(pkt, uint32(len(payload)))
	pkt[3] = seq
	pkt = append(pkt, payload...)
	_, err := conn.Write(pkt)
	require.NoError(t, err)
}

func requireServerHandshakeError(t *testing.T, err error, kind error, phase mysql.HandshakePhase) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, kind)

	var hsErr *mysql.HandshakeError
	require.ErrorAs(t, err, &hsErr)
	require.Equal(t, phase, hsErr.Phase)
	require.NotEmpty(t, hsErr.RemoteAddr)
	require.NotNil(t, hsErr.Timings)
	require.Contains(t, hsErr.Timings.String(), "greeting=")
	// Credentials must never leak into diagnostics.
	require.NotContains(t, err.Error(), "testpass")
}

func TestServerHandshakeCapabilityMismatch(t *testing.T) {
	authHandler := NewInMemoryAuthenticationHandler(mysql.AUTH_NATIVE_PASSWORD)
	require.NoError(t, authHandler.AddUser("testuser", "testpass"))

	addr, done := runFailingServer(t, NewDefaultServer(), authHandler)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_ = readClientPacket(t, conn) // server greeting

	// Response without CLIENT_PROTOCOL_41: the capability negotiation fails.
	caps := uint32(mysql.CLIENT_SECURE_CONNECTION)
	writeClientPacket(t, conn, 1, handshakeResponse(caps, "testuser"))

	// The server reports the failure as a plaintext ERR packet (the transport
	// is still intact), then closes the connection.
	resp := readClientPacket(t, conn)
	require.Equal(t, mysql.ERR_HEADER, resp[0])

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	requireServerHandshakeError(t, <-done, mysql.ErrHandshakeCapabilityMismatch, mysql.HandshakePhaseCapability)
}

func TestServerHandshakeAuthFailure(t *testing.T) {
	authHandler := NewInMemoryAuthenticationHandler(mysql.AUTH_NATIVE_PASSWORD)
	require.NoError(t, authHandler.AddUser("testuser", "testpass"))

	addr, done := runFailingServer(t, NewDefaultServer(), authHandler)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_ = readClientPacket(t, conn) // server greeting

	// Empty auth response against an account with a password.
	caps := uint32(mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION)
	writeClientPacket(t, conn, 1, handshakeResponse(caps, "testuser"))

	resp := readClientPacket(t, conn)
	require.Equal(t, mysql.ERR_HEADER, resp[0])
	require.Equal(t, uint16(mysql.ER_ACCESS_DENIED_ERROR), binary.LittleEndian.Uint16(resp[1:3]))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	hsErr := <-done
	requireServerHandshakeError(t, hsErr, mysql.ErrHandshakeAuth, mysql.HandshakePhaseAuth)
	// The auth phase timing distinguishes a fast credential rejection from
	// network jitter.
	require.Contains(t, hsErr.(*mysql.HandshakeError).Timings.String(), "auth=")
}

func TestServerHandshakeTLSFailure(t *testing.T) {
	tlsConf := NewServerTLSConfig(test_keys.CaPem, test_keys.CertPem, test_keys.KeyPem, tls.VerifyClientCertIfGiven)
	s := NewServer("8.0.36", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, test_keys.RSAKey(), tlsConf)

	authHandler := NewInMemoryAuthenticationHandler(mysql.AUTH_NATIVE_PASSWORD)
	require.NoError(t, authHandler.AddUser("testuser", "testpass"))

	addr, done := runFailingServer(t, s, authHandler)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_ = readClientPacket(t, conn) // server greeting

	// SSLRequest, then garbage instead of a TLS ClientHello.
	caps := uint32(mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_SSL)
	sslRequest := handshakeResponse(caps, "")[:4+4+1+23]
	writeClientPacket(t, conn, 1, sslRequest)
	_, err = conn.Write([]byte("this is not a TLS ClientHello"))
	require.NoError(t, err)

	// The server must not answer the broken TLS stream with a plaintext ERR
	// packet, and must not parse the following bytes as plaintext: the
	// connection is simply closed.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	requireServerHandshakeError(t, <-done, mysql.ErrHandshakeTLS, mysql.HandshakePhaseTLS)
}
