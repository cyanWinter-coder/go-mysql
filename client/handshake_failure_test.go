package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// fakeServerCaps mirrors the capability set of a recent MySQL server.
const fakeServerCaps = mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG |
	mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION |
	mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_TRANSACTIONS

// fakeServer runs script on the first accepted connection and reports the
// script's result on the returned channel.
func fakeServer(t *testing.T, script func(conn net.Conn) error) (string, <-chan error) {
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
		done <- script(conn)
	}()
	return l.Addr().String(), done
}

// serverGreeting builds a Protocol::HandshakeV10 packet with the given
// capability flags and auth plugin name.
func serverGreeting(capability uint32, authPlugin string) []byte {
	payload := []byte{mysql.ClassicProtocolVersion}
	payload = append(payload, "8.0.36-fake"...)
	payload = append(payload, 0x00)
	payload = append(payload, 1, 0, 0, 0) // connection id
	payload = append(payload, "12345678"...)
	payload = append(payload, 0x00)
	payload = append(payload, byte(capability), byte(capability>>8))
	payload = append(payload, 45)   // utf8mb4 charset
	payload = append(payload, 2, 0) // SERVER_STATUS_AUTOCOMMIT
	payload = append(payload, byte(capability>>16), byte(capability>>24))
	payload = append(payload, 21) // auth plugin data len
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, "abcdefghijkl"...)
	payload = append(payload, 0x00)
	payload = append(payload, authPlugin...)
	payload = append(payload, 0x00)

	pkt := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(pkt, uint32(len(payload)))
	pkt[3] = 0 // sequence id
	return append(pkt, payload...)
}

// readWirePacket reads one full MySQL packet from conn.
func readWirePacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, length)
	_, err := io.ReadFull(conn, payload)
	return payload, err
}

// writeWirePacket writes payload as a MySQL packet with the given sequence id.
func writeWirePacket(conn net.Conn, seq byte, payload []byte) error {
	pkt := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(pkt, uint32(len(payload)))
	pkt[3] = seq
	pkt = append(pkt, payload...)
	_, err := conn.Write(pkt)
	return err
}

// accessDeniedPacket builds an ERR packet for ER_ACCESS_DENIED_ERROR.
func accessDeniedPacket() []byte {
	payload := []byte{mysql.ERR_HEADER, 0, 0}
	binary.LittleEndian.PutUint16(payload[1:3], mysql.ER_ACCESS_DENIED_ERROR)
	payload = append(payload, '#')
	payload = append(payload, "28000"...)
	payload = append(payload, "Access denied for user 'testuser'@'localhost' (using password: YES)"...)
	return payload
}

// requireHandshakeError asserts err is a *mysql.HandshakeError of the given
// kind and phase, carrying the peer address, and free of credentials.
func requireHandshakeError(t *testing.T, err error, kind error, phase mysql.HandshakePhase, remoteAddr string) *mysql.HandshakeError {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, kind)

	var hsErr *mysql.HandshakeError
	require.ErrorAs(t, err, &hsErr)
	require.Equal(t, phase, hsErr.Phase)
	require.Equal(t, remoteAddr, hsErr.RemoteAddr)
	require.NotNil(t, hsErr.Timings)
	require.NotContains(t, err.Error(), "s3cret-token")
	return hsErr
}

func TestHandshakeCapabilityMismatchNoProtocol41(t *testing.T) {
	addr, done := fakeServer(t, func(conn net.Conn) error {
		// Greeting without CLIENT_PROTOCOL_41.
		if _, err := conn.Write(serverGreeting(fakeServerCaps&^mysql.CLIENT_PROTOCOL_41, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		// The client must abort and close; it must not send a handshake response.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := readWirePacket(conn)
		require.ErrorIs(t, err, io.EOF)
		return nil
	})

	_, err := Connect(addr, "testuser", "s3cret-token", "testdb")
	hsErr := requireHandshakeError(t, err, mysql.ErrHandshakeCapabilityMismatch, mysql.HandshakePhaseCapability, addr)
	require.GreaterOrEqual(t, hsErr.Timings.Duration(mysql.HandshakePhaseGreeting), time.Duration(0))
	require.NoError(t, <-done)
}

func TestHandshakeCapabilityMismatchTLSNotSupported(t *testing.T) {
	addr, done := fakeServer(t, func(conn net.Conn) error {
		// Greeting without CLIENT_SSL while the client requires TLS.
		if _, err := conn.Write(serverGreeting(fakeServerCaps, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := readWirePacket(conn)
		require.ErrorIs(t, err, io.EOF)
		return nil
	})

	_, err := Connect(addr, "testuser", "s3cret-token", "testdb", func(c *Conn) error {
		c.UseSSL(true)
		return nil
	})
	requireHandshakeError(t, err, mysql.ErrHandshakeCapabilityMismatch, mysql.HandshakePhaseCapability, addr)
	require.NoError(t, <-done)
}

func TestHandshakeTLSFailure(t *testing.T) {
	addr, done := fakeServer(t, func(conn net.Conn) error {
		if _, err := conn.Write(serverGreeting(fakeServerCaps|mysql.CLIENT_SSL, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		// Read the SSLRequest packet, then answer the TLS ClientHello with
		// garbage so the TLS negotiation fails.
		if _, err := readWirePacket(conn); err != nil {
			return err
		}
		if _, err := conn.Write([]byte("this is not a TLS record")); err != nil {
			return err
		}
		// The client must close after the failed TLS handshake.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := io.Copy(io.Discard, conn)
		return err
	})

	_, err := Connect(addr, "testuser", "s3cret-token", "testdb", func(c *Conn) error {
		c.UseSSL(true)
		return nil
	})
	hsErr := requireHandshakeError(t, err, mysql.ErrHandshakeTLS, mysql.HandshakePhaseTLS, addr)
	// The TLS phase timing lets operators tell a slow network from a broken
	// TLS setup.
	require.Contains(t, hsErr.Timings.String(), "tls=")
	require.NoError(t, <-done)
}

func TestHandshakeAuthFailure(t *testing.T) {
	addr, done := fakeServer(t, func(conn net.Conn) error {
		if _, err := conn.Write(serverGreeting(fakeServerCaps, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		// Read the handshake response, then reject the credentials.
		if _, err := readWirePacket(conn); err != nil {
			return err
		}
		if err := writeWirePacket(conn, 2, accessDeniedPacket()); err != nil {
			return err
		}
		// The client must close after the failed authentication.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := readWirePacket(conn)
		require.ErrorIs(t, err, io.EOF)
		return nil
	})

	_, err := Connect(addr, "testuser", "s3cret-token", "testdb")
	hsErr := requireHandshakeError(t, err, mysql.ErrHandshakeAuth, mysql.HandshakePhaseAuth, addr)
	// Greeting and auth phases were timed; the failure was fast, pointing at
	// credentials rather than the network.
	require.Contains(t, hsErr.Timings.String(), "greeting=")
	require.Contains(t, hsErr.Timings.String(), "auth=")
	require.NoError(t, <-done)
}

func TestHandshakeUnknownAuthPlugin(t *testing.T) {
	addr, done := fakeServer(t, func(conn net.Conn) error {
		if _, err := conn.Write(serverGreeting(fakeServerCaps, "auth_plugin_from_the_future")); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := readWirePacket(conn)
		require.ErrorIs(t, err, io.EOF)
		return nil
	})

	_, err := Connect(addr, "testuser", "s3cret-token", "testdb")
	requireHandshakeError(t, err, mysql.ErrHandshakeCapabilityMismatch, mysql.HandshakePhaseCapability, addr)
	require.NoError(t, <-done)
}

// TestHandshakeRetryGetsFreshState: a retry after a failed handshake connects
// with completely fresh state and succeeds.
func TestHandshakeRetryGetsFreshState(t *testing.T) {
	failAddr, failDone := fakeServer(t, func(conn net.Conn) error {
		if _, err := conn.Write(serverGreeting(fakeServerCaps, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		if _, err := readWirePacket(conn); err != nil {
			return err
		}
		return writeWirePacket(conn, 2, accessDeniedPacket())
	})

	_, err := Connect(failAddr, "testuser", "s3cret-token", "testdb")
	requireHandshakeError(t, err, mysql.ErrHandshakeAuth, mysql.HandshakePhaseAuth, failAddr)
	require.NoError(t, <-failDone)

	okAddr, okDone := fakeServer(t, func(conn net.Conn) error {
		if _, err := conn.Write(serverGreeting(fakeServerCaps, mysql.AUTH_NATIVE_PASSWORD)); err != nil {
			return err
		}
		if _, err := readWirePacket(conn); err != nil {
			return err
		}
		// OK packet: header, affected rows, last insert id, status, warnings.
		return writeWirePacket(conn, 2, []byte{mysql.OK_HEADER, 0, 0, 2, 0, 0, 0})
	})

	c, err := Connect(okAddr, "testuser", "s3cret-token", "testdb")
	require.NoError(t, err)
	require.True(t, c.HandshakeCompleted())
	require.Contains(t, c.HandshakeTimings().String(), "auth=")
	require.NoError(t, c.Close())
	require.NoError(t, <-okDone)
}

// TestPoolHandshakeFailuresNotReturned: connections that fail the handshake
// are closed and never returned to the pool; the stats show the failures.
func TestPoolHandshakeFailuresNotReturned(t *testing.T) {
	// A listener that accepts and immediately closes every connection makes
	// every handshake fail.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	pool, err := NewPoolWithOptions(l.Addr().String(), "testuser", "s3cret-token", "testdb",
		WithPoolLimits(0, 1, 0),
	)
	require.NoError(t, err)
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = pool.GetConn(ctx)
	require.Error(t, err)

	var stats ConnectionStats
	pool.GetStats(&stats)
	require.Positive(t, stats.FailedCount)
	require.Zero(t, stats.TotalCount)
	require.Zero(t, stats.CreatedCount)
	require.Zero(t, stats.IdleCount)
}

// TestPoolPutConnRejectsIncompleteHandshake: a connection that never
// completed its handshake is closed and accounted for, not pooled.
func TestPoolPutConnRejectsIncompleteHandshake(t *testing.T) {
	pool, err := NewPoolWithOptions("127.0.0.1:1", "u", "p", "db",
		WithPoolLimits(0, 1, 0),
	)
	require.NoError(t, err)
	defer pool.Close()

	pool.PutConn(nil)
	pool.PutConn(&Conn{}) // never connected, handshake not completed

	var stats ConnectionStats
	pool.GetStats(&stats)
	require.Equal(t, int64(1), stats.FailedCount)
	require.Zero(t, stats.IdleCount)
}
