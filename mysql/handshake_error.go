package mysql

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// HandshakePhase identifies a stage of the MySQL connection-phase
// negotiation. The phases are negotiated in a fixed protocol order:
// the server greeting (which carries the capability advertisement),
// the capability negotiation, the optional TLS upgrade, and the
// authentication exchange. A failure in one phase aborts the
// handshake; later phases are never attempted.
type HandshakePhase string

const (
	// HandshakePhaseGreeting is the server greeting (initial handshake packet).
	HandshakePhaseGreeting HandshakePhase = "greeting"
	// HandshakePhaseCapability is the capability flag negotiation.
	HandshakePhaseCapability HandshakePhase = "capability"
	// HandshakePhaseTLS is the TLS upgrade of the connection.
	HandshakePhaseTLS HandshakePhase = "tls"
	// HandshakePhaseAuth is the authentication exchange.
	HandshakePhaseAuth HandshakePhase = "auth"
)

// Stable identifiers for the classes of handshake negotiation failure.
// Test for them with errors.Is; their message text is not part of the API.
var (
	// ErrHandshakeCapabilityMismatch marks a failure to agree on capability
	// flags (e.g. the peer lacks CLIENT_PROTOCOL_41, or TLS/compression was
	// required but not advertised).
	ErrHandshakeCapabilityMismatch = errors.New("mysql: capability mismatch during handshake")
	// ErrHandshakeTLS marks a failed TLS negotiation during the handshake.
	ErrHandshakeTLS = errors.New("mysql: TLS negotiation failed during handshake")
	// ErrHandshakeAuth marks an authentication failure during the handshake
	// (e.g. the peer rejected the credentials).
	ErrHandshakeAuth = errors.New("mysql: authentication failed during handshake")
)

// HandshakeTimings records how long each completed negotiation phase took,
// so a failure report can distinguish a slow network (long greeting/TLS
// phases) from a fast credential rejection (short phases, failing in auth).
type HandshakeTimings struct {
	phases []HandshakePhase
	durs   map[HandshakePhase]time.Duration
}

func NewHandshakeTimings() *HandshakeTimings {
	return &HandshakeTimings{durs: make(map[HandshakePhase]time.Duration)}
}

// Record adds d to the accumulated duration of phase.
func (t *HandshakeTimings) Record(phase HandshakePhase, d time.Duration) {
	if t == nil {
		return
	}
	if _, ok := t.durs[phase]; !ok {
		t.phases = append(t.phases, phase)
	}
	t.durs[phase] += d
}

// Duration returns the accumulated duration of a phase.
func (t *HandshakeTimings) Duration(phase HandshakePhase) time.Duration {
	if t == nil {
		return 0
	}
	return t.durs[phase]
}

// String renders the timings in recording order, e.g. "greeting=1.2ms tls=300µs".
func (t *HandshakeTimings) String() string {
	if t == nil || len(t.phases) == 0 {
		return "-"
	}
	var b strings.Builder
	for i, phase := range t.phases {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", phase, t.durs[phase].Round(time.Microsecond))
	}
	return b.String()
}

// HandshakeError describes a failed connection-phase negotiation. It carries
// the phase the negotiation aborted in, the peer address, and the per-phase
// timings collected up to the failure. It never carries credentials: Err
// must not contain passwords or authentication tokens.
type HandshakeError struct {
	// Phase is the negotiation phase that failed.
	Phase HandshakePhase
	// Kind is one of the ErrHandshake* sentinels classifying the failure,
	// or nil for failures without a stable classification (e.g. a malformed
	// packet or a network error).
	Kind error
	// RemoteAddr is the address of the peer the handshake was negotiated with.
	RemoteAddr string
	// Timings holds the per-phase durations collected up to the failure.
	Timings *HandshakeTimings
	// Err is the underlying error.
	Err error
}

func (e *HandshakeError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "handshake failed in %s phase", e.Phase)
	if e.RemoteAddr != "" {
		fmt.Fprintf(&b, " (remote %s)", e.RemoteAddr)
	}
	if e.Timings != nil {
		fmt.Fprintf(&b, " [%s]", e.Timings)
	}
	fmt.Fprintf(&b, ": %v", e.Err)
	return b.String()
}

// Unwrap exposes both the stable failure classification (if any) and the
// underlying error, so errors.Is matches either.
func (e *HandshakeError) Unwrap() []error {
	if e.Kind == nil {
		return []error{e.Err}
	}
	return []error{e.Kind, e.Err}
}
