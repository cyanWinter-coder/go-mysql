package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/packet"
)

func TestServerReadProtectionConfig(t *testing.T) {
	s := NewDefaultServer()

	// Defaults: no per-connection cap, no shared limiter.
	require.Zero(t, s.MaxPacketSize())
	require.Nil(t, s.ReadLimiter())

	s.SetMaxPacketSize(32 << 20)
	require.Equal(t, 32<<20, s.MaxPacketSize())

	limiter := packet.NewReadLimiter(64 << 20)
	s.SetReadLimiter(limiter)
	require.Same(t, limiter, s.ReadLimiter())

	// Reconfiguring affects the stored settings that NewCustomizedConn reads.
	s.SetMaxPacketSize(0)
	require.Zero(t, s.MaxPacketSize())
	s.SetReadLimiter(nil)
	require.Nil(t, s.ReadLimiter())
}

func TestReadLimiterIndependenceAcrossConnections(t *testing.T) {
	// A shared budget must not let one connection reserve capacity it will
	// never release. Each acquire/release pair is independent, and exhaustion
	// for one claimant leaves the limiter usable for others after release.
	limiter := packet.NewReadLimiter(1024)

	require.True(t, limiter.Acquire(512))
	require.EqualValues(t, 512, limiter.Used())
	// A second, larger reservation is refused rather than queued.
	require.False(t, limiter.Acquire(1024))
	require.EqualValues(t, 512, limiter.Used(), "refused acquire must not change usage")

	// Releasing frees the budget for the next connection.
	limiter.Release(512)
	require.EqualValues(t, 0, limiter.Used())
	require.True(t, limiter.Acquire(1024))
	require.EqualValues(t, 1024, limiter.Used())
}
