package client

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/packet"
)

// The client options only mutate configuration on a not-yet-connected Conn,
// so they can be exercised without a live MySQL server.
func TestReadProtectionOptions(t *testing.T) {
	t.Run("max packet size", func(t *testing.T) {
		c := new(Conn)
		require.NoError(t, WithMaxPacketSize(4096)(c))
		require.Equal(t, 4096, c.MaxPacketSize)

		require.Error(t, WithMaxPacketSize(-1)(c))
	})

	t.Run("read limiter", func(t *testing.T) {
		c := new(Conn)
		limiter := packet.NewReadLimiter(1 << 20)
		require.NoError(t, WithReadLimiter(limiter)(c))
		require.Same(t, limiter, c.ReadLimiter)
	})

	t.Run("read logger", func(t *testing.T) {
		c := new(Conn)
		logger := slog.Default()
		require.NoError(t, WithReadLogger(logger)(c))
		require.Same(t, logger, c.readLogger)
	})
}
