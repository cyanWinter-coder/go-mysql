package mysql

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHandshakeTimingsString(t *testing.T) {
	var nilTimings *HandshakeTimings
	require.Equal(t, "-", nilTimings.String())
	require.Equal(t, "-", NewHandshakeTimings().String())

	timings := NewHandshakeTimings()
	timings.Record(HandshakePhaseGreeting, 1200*time.Microsecond)
	timings.Record(HandshakePhaseTLS, 300*time.Microsecond)
	timings.Record(HandshakePhaseGreeting, 100*time.Microsecond)

	require.Equal(t, "greeting=1.3ms tls=300µs", timings.String())
	require.Equal(t, 1300*time.Microsecond, timings.Duration(HandshakePhaseGreeting))
	require.Equal(t, 300*time.Microsecond, timings.Duration(HandshakePhaseTLS))
	require.Equal(t, time.Duration(0), timings.Duration(HandshakePhaseAuth))
}

func TestHandshakeError(t *testing.T) {
	inner := errors.New("server rejected credentials")
	timings := NewHandshakeTimings()
	timings.Record(HandshakePhaseGreeting, time.Millisecond)

	err := &HandshakeError{
		Phase:      HandshakePhaseAuth,
		Kind:       ErrHandshakeAuth,
		RemoteAddr: "127.0.0.1:3306",
		Timings:    timings,
		Err:        inner,
	}

	msg := err.Error()
	require.Contains(t, msg, "auth")
	require.Contains(t, msg, "127.0.0.1:3306")
	require.Contains(t, msg, "greeting=1ms")
	require.Contains(t, msg, "server rejected credentials")

	// errors.Is matches both the stable classification and the cause.
	require.ErrorIs(t, err, ErrHandshakeAuth)
	require.ErrorIs(t, err, inner)
	require.NotErrorIs(t, err, ErrHandshakeTLS)
	require.NotErrorIs(t, err, ErrHandshakeCapabilityMismatch)

	// A nil Kind still unwraps to the cause.
	noKind := &HandshakeError{Phase: HandshakePhaseGreeting, Err: inner}
	require.ErrorIs(t, noKind, inner)
	require.NotErrorIs(t, noKind, ErrHandshakeAuth)
}

func TestHandshakeErrorNoSecrets(t *testing.T) {
	// The diagnostic message is built from phase, address, timings and the
	// wrapped error only; nothing pulls in credentials automatically.
	err := &HandshakeError{
		Phase:      HandshakePhaseAuth,
		Kind:       ErrHandshakeAuth,
		RemoteAddr: "10.0.0.1:3306",
		Timings:    NewHandshakeTimings(),
		Err:        fmt.Errorf("%w", ErrHandshakeAuth),
	}
	require.NotContains(t, err.Error(), "password")
}
