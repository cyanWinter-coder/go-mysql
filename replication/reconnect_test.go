package replication

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
)

// binlogPacket wraps an event payload (OK byte + 19-byte header + body) in a
// MySQL length-encoded packet with the given sequence id.
func binlogPacket(seq byte, payload []byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

func heartbeatPayload(eventType EventType, logPos uint32, ts uint32) []byte {
	p := make([]byte, 1+EventHeaderSize)
	p[0] = mysql.OK_HEADER
	p[1+4] = byte(eventType)
	binary.LittleEndian.PutUint32(p[1:], ts)
	binary.LittleEndian.PutUint32(p[1+9:], EventHeaderSize)
	binary.LittleEndian.PutUint32(p[1+13:], logPos)
	return p
}

// TestOnStreamReconnectReplaysWithOriginalPosition drives the full reconnect
// loop with deterministic in-memory connections:
//  1. the first connection delivers events up to a high-water mark,
//  2. the connection drops while the confirmed checkpoint is behind it,
//  3. the second connection re-serves the unconfirmed events,
//  4. the replayed events carry Replay=true and their original positions,
//  5. events past the old high-water mark are new again.
func TestOnStreamReconnectReplaysWithOriginalPosition(t *testing.T) {
	const (
		file        = "mysql-bin.000001"
		startPos    = uint32(4)
		confirmedAt = uint32(123) // downstream only confirmed through here
	)

	// Generation 0: events [4,123) and [123,200). Generation 1 replays from
	// the confirmed checkpoint 123, then continues with a new event past 200.
	gen0 := [][]byte{
		// A brand new connection starts its packet sequence at 0.
		binlogPacket(0, heartbeatPayload(HEARTBEAT_EVENT, 123, 100)),
		binlogPacket(1, heartbeatPayload(HEARTBEAT_EVENT, 200, 101)),
	}
	gen1 := [][]byte{
		// A fresh connection resets its packet sequence to 0.
		binlogPacket(0, heartbeatPayload(HEARTBEAT_EVENT, 200, 101)), // replay of the [123,200) event
		binlogPacket(1, heartbeatPayload(HEARTBEAT_EVENT, 300, 102)), // new event
	}

	// Each reconnect generation is backed by its own net.Pipe pair: the
	// syncer side replaces b.c, the test side scripts packets and eventually
	// closes to trigger the next generation.
	var serverConns []net.Conn
	var clientConns []net.Conn
	for range 2 {
		cli, srv := net.Pipe()
		clientConns = append(clientConns, cli)
		serverConns = append(serverConns, srv)
	}

	var reconnects []ReconnectStatus
	b := NewBinlogSyncer(BinlogSyncerConfig{
		ServerID:          100,
		ManualCheckpoint:  true,
		ReconnectInterval: 20 * time.Millisecond,
		Logger:            slog.New(slog.NewTextHandler(&testLogWriter{t: t}, nil)),
		OnReconnect: func(status ReconnectStatus) {
			reconnects = append(reconnects, status)
		},
	})
	t.Cleanup(b.Close)

	start := mysql.Position{Name: file, Pos: startPos}
	// Mirror StartSync's initial checkpoint state: the start position is the
	// first confirmed point; resumeReplay stays off until a reconnect.
	b.nextPos = start
	b.confirmedPos = start
	b.running = true
	b.c = &client.Conn{Conn: packet.NewConn(clientConns[0])}

	script := func(srv net.Conn, packets [][]byte) {
		for _, pkt := range packets {
			if _, err := srv.Write(pkt); err != nil {
				return
			}
		}
	}

	gen := 0
	b.retryHook = func() error {
		gen++
		require.Less(t, gen, len(clientConns), "unexpected extra reconnect generation")
		// Swap in the next generation's connection exactly like registerSlave
		// would replace b.c after a real reconnect, then script its stream.
		// ResetSequence mirrors the fresh connection a real dial produces.
		next := &client.Conn{Conn: packet.NewConn(clientConns[gen])}
		next.ResetSequence()
		b.c = next
		go script(serverConns[gen], gen1)
		return nil
	}

	s := NewBinlogStreamerWithChanSize(8)
	b.wg.Add(1)
	go b.onStream(s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go script(serverConns[0], gen0)

	// Consume the two generation-0 events.
	ev1, err := s.GetEvent(ctx)
	require.NoError(t, err)
	require.False(t, ev1.Replay)
	require.Equal(t, uint32(4), ev1.StreamPosition.Pos)
	require.Equal(t, uint32(123), ev1.Header.LogPos)

	ev2, err := s.GetEvent(ctx)
	require.NoError(t, err)
	require.False(t, ev2.Replay)
	require.Equal(t, uint32(123), ev2.StreamPosition.Pos)
	require.Equal(t, uint32(200), ev2.Header.LogPos)

	// High-water is 200 but the downstream only confirmed 123.
	require.Equal(t, uint32(200), b.GetNextPosition().Pos)
	require.NoError(t, b.AcknowledgePosition(mysql.Position{Name: file, Pos: confirmedAt}))

	// Break the first connection; onStream retries through retryHook, which
	// installs generation 1.
	require.NoError(t, serverConns[0].Close())
	require.NoError(t, clientConns[0].Close())

	// The replayed event must keep origin 123 and be flagged.
	replay, err := s.GetEvent(ctx)
	require.NoError(t, err)
	require.True(t, replay.Replay, "unconfirmed event must be replayed with the dedup flag set")
	require.Equal(t, mysql.Position{Name: file, Pos: 123}, replay.StreamPosition)

	// The following event moves past the old high-water mark and is new.
	fresh, err := s.GetEvent(ctx)
	require.NoError(t, err)
	require.False(t, fresh.Replay)
	require.Equal(t, uint32(200), fresh.StreamPosition.Pos)
	require.Equal(t, uint32(300), fresh.Header.LogPos)

	// The reconnect callback fired and reported the confirmed resume point.
	require.Len(t, reconnects, 1)
	require.Equal(t, confirmedAt, reconnects[0].Checkpoint.Position.Pos)
	require.Equal(t, file, reconnects[0].Checkpoint.Position.Name)

	// Manual mode: the confirmed checkpoint is still where the downstream
	// acknowledged, the syncer never advanced it on its own.
	require.Equal(t, confirmedAt, b.ConfirmedCheckpoint().Position.Pos)
}

// TestOnStreamResumePositionUnavailableStops ensures a 1236 on reconnect
// terminates the stream with a typed error instead of looping forever or
// silently jumping to the newest binlog.
func TestOnStreamResumePositionUnavailableStops(t *testing.T) {
	b := NewBinlogSyncer(BinlogSyncerConfig{
		ServerID:          100,
		ManualCheckpoint:  true,
		ReconnectInterval: 20 * time.Millisecond,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	t.Cleanup(b.Close)

	start := mysql.Position{Name: "mysql-bin.000001", Pos: 4}
	b.nextPos = start
	b.confirmedPos = start
	b.running = true

	// Force every reconnect attempt to fail with the server's purge error.
	fatal := mysql.NewDefaultError(mysql.ER_MASTER_FATAL_ERROR_READING_BINLOG,
		"Could not find first log file name in binary log index file")
	b.retryHook = func() error { return fatal }

	raw, peer := net.Pipe()
	b.c = &client.Conn{Conn: packet.NewConn(raw)}
	s := NewBinlogStreamer()
	b.wg.Add(1)
	go b.onStream(s)

	_ = peer.Close()
	_ = raw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.GetEvent(ctx)
	require.Error(t, err)
	var unavailable *ResumePositionUnavailableError
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, "mysql-bin.000001", unavailable.Resume.Position.Name)
}
