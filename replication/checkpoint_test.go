package replication

import (
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pingcap/errors"
	"github.com/stretchr/testify/require"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func newTestSyncer(t *testing.T, manual bool) *BinlogSyncer {
	b := NewBinlogSyncer(BinlogSyncerConfig{
		ServerID:         1,
		ManualCheckpoint: manual,
		Logger:           slog.New(slog.NewTextHandler(&testLogWriter{t: t}, nil)),
	})
	t.Cleanup(b.Close)
	return b
}

type testLogWriter struct{ t *testing.T }

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

// TestCheckpointStringAndZero covers the basic Checkpoint rendering used in
// reconnect logs and error messages.
func TestCheckpointStringAndZero(t *testing.T) {
	cp := Checkpoint{}
	require.True(t, cp.IsZero())
	require.Contains(t, cp.String(), "position=")

	cp = Checkpoint{Position: mysql.Position{Name: "mysql-bin.000002", Pos: 1234}}
	require.False(t, cp.IsZero())
	require.Contains(t, cp.String(), "mysql-bin.000002")
	require.Contains(t, cp.String(), "1234")

	gset, err := mysql.ParseMysqlGTIDSet("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:1-5")
	require.NoError(t, err)
	cp = Checkpoint{GTIDSet: gset}
	require.False(t, cp.IsZero())
	require.Contains(t, cp.String(), "gtid_set=")
}

// TestAcknowledgePositionMonotonic ensures a downstream acknowledgement can
// never move the confirmed position backwards, which would let the syncer
// resume before already-applied events.
func TestAcknowledgePositionMonotonic(t *testing.T) {
	b := newTestSyncer(t, true)

	p1 := mysql.Position{Name: "mysql-bin.000001", Pos: 100}
	require.NoError(t, b.AcknowledgePosition(p1))
	require.Equal(t, p1, b.ConfirmedCheckpoint().Position)

	// Same position is allowed (idempotent retry of the acknowledgement).
	require.NoError(t, b.AcknowledgePosition(p1))

	// Backwards within the same file is rejected.
	require.Error(t, b.AcknowledgePosition(mysql.Position{Name: "mysql-bin.000001", Pos: 99}))
	// An older file is rejected.
	require.Error(t, b.AcknowledgePosition(mysql.Position{Name: "mysql-bin.000000", Pos: 9999}))

	p2 := mysql.Position{Name: "mysql-bin.000001", Pos: 200}
	require.NoError(t, b.AcknowledgePosition(p2))
	require.Equal(t, p2, b.ConfirmedCheckpoint().Position)
}

// TestAcknowledgeGTIDMonotonic ensures the confirmed GTID set only grows: an
// acknowledgement that drops an already-confirmed transaction is rejected.
func TestAcknowledgeGTIDMonotonic(t *testing.T) {
	b := newTestSyncer(t, true)

	require.Error(t, b.AcknowledgeGTID(nil))

	base, err := mysql.ParseMysqlGTIDSet("de278ad0-2106-11e4-9f8e-6edd0ca20947:1-5")
	require.NoError(t, err)
	require.NoError(t, b.AcknowledgeGTID(base))
	require.Equal(t, base.String(), b.ConfirmedCheckpoint().GTIDSet.String())

	// A disjoint set does not contain the confirmed one and must be rejected.
	other, err := mysql.ParseMysqlGTIDSet("de278ad0-2106-11e4-9f8e-6edd0ca20947:7-9")
	require.NoError(t, err)
	require.Error(t, b.AcknowledgeGTID(other))

	// A superset is accepted.
	superset, err := mysql.ParseMysqlGTIDSet("de278ad0-2106-11e4-9f8e-6edd0ca20947:1-9")
	require.NoError(t, err)
	require.NoError(t, b.AcknowledgeGTID(superset))
	require.Equal(t, superset.String(), b.ConfirmedCheckpoint().GTIDSet.String())
}

// TestAutoCheckpointAdvancesWithEvents verifies the legacy default mode keeps
// advancing the confirmed checkpoint as events are parsed and delivered, so
// existing users see unchanged resume behaviour.
func TestAutoCheckpointAdvancesWithEvents(t *testing.T) {
	b := newTestSyncer(t, false)
	b.nextPos = mysql.Position{Name: "mysql-bin.000001", Pos: 4}
	b.confirmedPos = b.nextPos

	s := NewBinlogStreamer()
	ev := &BinlogEvent{
		Header: &EventHeader{EventType: QUERY_EVENT, LogPos: 120, Timestamp: 1},
		Event:  &QueryEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, ev, false))

	// Auto mode: confirmed follows the high-water mark; the event is not a
	// replay on a fresh stream.
	require.False(t, ev.Replay)
	require.Equal(t, uint32(120), b.ConfirmedCheckpoint().Position.Pos)
	require.Equal(t, mysql.Position{Name: "mysql-bin.000001", Pos: 4}, ev.StreamPosition)
}

// TestManualCheckpointHoldsUntilAcknowledged verifies that in manual mode the
// confirmed checkpoint does not move when events are merely delivered, and
// only moves on explicit acknowledgement. This is the guarantee that
// position advancement stays inside the downstream's apply transaction.
func TestManualCheckpointHoldsUntilAcknowledged(t *testing.T) {
	b := newTestSyncer(t, true)
	start := mysql.Position{Name: "mysql-bin.000001", Pos: 4}
	b.confirmedPos = start
	b.nextPos = start

	s := NewBinlogStreamer()
	ev := &BinlogEvent{
		Header: &EventHeader{EventType: XID_EVENT, LogPos: 300, Timestamp: 1},
		Event:  &XIDEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, ev, false))

	// The high-water mark moved ...
	require.Equal(t, uint32(300), b.nextPos.Pos)
	// ... but the confirmed checkpoint did not.
	require.Equal(t, start, b.ConfirmedCheckpoint().Position)

	require.NoError(t, b.AcknowledgePosition(mysql.Position{Name: "mysql-bin.000001", Pos: 300}))
	require.Equal(t, uint32(300), b.ConfirmedCheckpoint().Position.Pos)
}

// TestResumeCheckpointUsesConfirmedNotHighWater is the core reconnect
// invariant: with manual checkpoints, resume must use the confirmed position
// even though the parser read further ahead.
func TestResumeCheckpointUsesConfirmedNotHighWater(t *testing.T) {
	b := newTestSyncer(t, true)
	b.confirmedPos = mysql.Position{Name: "mysql-bin.000001", Pos: 100}
	b.nextPos = mysql.Position{Name: "mysql-bin.000001", Pos: 500}

	cp := b.resumeCheckpoint()
	require.Equal(t, uint32(100), cp.Position.Pos)
	require.Nil(t, cp.GTIDSet)

	// Legacy mode instead resumes at the high-water mark.
	b.cfg.ManualCheckpoint = false
	cp = b.resumeCheckpoint()
	require.Equal(t, uint32(500), cp.Position.Pos)
}

// TestPositionModeReplayFlag simulates a reconnect: events already observed
// before the disconnect are replayed from the confirmed checkpoint and must
// carry Replay=true with their original positions; events past the old
// high-water mark are new.
func TestPositionModeReplayFlag(t *testing.T) {
	b := newTestSyncer(t, true)
	b.confirmedPos = mysql.Position{Name: "mysql-bin.000001", Pos: 100}
	b.nextPos = mysql.Position{Name: "mysql-bin.000001", Pos: 500}

	// Simulate what retrySync does just before opening the new stream.
	cp := b.resumeCheckpoint()
	b.markReplayBoundary(cp)
	require.True(t, b.resumeReplay)
	require.Equal(t, uint32(500), b.resumeBoundaryPos.Pos)
	// The high-water mark is rewound to the confirmed resume position.
	require.Equal(t, uint32(100), b.nextPos.Pos)

	s := NewBinlogStreamer()

	// The new stream replays from 100: an event covering [100,200).
	first := &BinlogEvent{
		Header: &EventHeader{EventType: WRITE_ROWS_EVENTv2, LogPos: 200, Timestamp: 2},
		Event:  &RowsEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, first, false))
	require.True(t, first.Replay, "event at or before the old high-water mark must be flagged as replay")
	require.Equal(t, mysql.Position{Name: "mysql-bin.000001", Pos: 100}, first.StreamPosition,
		"replayed event must keep its original origin position for dedup")

	// Next event [200,500) is still within the old window: also a replay.
	second := &BinlogEvent{
		Header: &EventHeader{EventType: XID_EVENT, LogPos: 500, Timestamp: 2},
		Event:  &XIDEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, second, false))
	require.True(t, second.Replay)
	require.Equal(t, uint32(200), second.StreamPosition.Pos)

	// Event [500,600) moves past the boundary and is new.
	third := &BinlogEvent{
		Header: &EventHeader{EventType: WRITE_ROWS_EVENTv2, LogPos: 600, Timestamp: 3},
		Event:  &RowsEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, third, false))
	require.False(t, third.Replay)
	require.Equal(t, uint32(500), third.StreamPosition.Pos)

	// Manual mode: nothing was confirmed, so the reconnect point is still 100.
	require.Equal(t, uint32(100), b.ConfirmedCheckpoint().Position.Pos)
}

// TestPositionModeReplayDisabledInLegacyMode ensures default users do not get
// replay flags: without manual checkpoints the resume point equals the
// high-water mark so no replay window exists.
func TestPositionModeReplayDisabledInLegacyMode(t *testing.T) {
	b := newTestSyncer(t, false)
	b.nextPos = mysql.Position{Name: "mysql-bin.000001", Pos: 500}

	b.markReplayBoundary(b.resumeCheckpoint())
	require.False(t, b.resumeReplay)

	s := NewBinlogStreamer()
	ev := &BinlogEvent{
		Header: &EventHeader{EventType: WRITE_ROWS_EVENTv2, LogPos: 600, Timestamp: 2},
		Event:  &RowsEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, ev, false))
	require.False(t, ev.Replay)
}

// TestGTIDModeReplayFlag verifies GTID-based replay classification: the
// transaction whose GTID is inside the pre-disconnect boundary is a replay
// (GTID event and its XID both flagged), the next transaction is new.
func TestGTIDModeReplayFlag(t *testing.T) {
	const sid = "de278ad0-2106-11e4-9f8e-6edd0ca20947"
	u := uuid.MustParse(sid)

	b := newTestSyncer(t, true)
	prev, err := mysql.ParseMysqlGTIDSet(sid + ":1-3")
	require.NoError(t, err)
	b.prevGset = prev
	b.currGset = prev.Clone()
	b.confirmedGset = prev.Clone()

	// Boundary after the disconnect contains transactions up to GNO 4.
	boundary, err := mysql.ParseMysqlGTIDSet(sid + ":1-4")
	require.NoError(t, err)
	b.resumeBoundaryGset = boundary
	b.resumeReplay = true

	s := NewBinlogStreamer()

	// Replayed transaction GNO 4: GTID event and XID must both be flagged.
	gtidReplay := &BinlogEvent{
		Header: &EventHeader{EventType: GTID_EVENT, Timestamp: 2},
		Event:  &GTIDEvent{SID: u[:], GNO: 4},
	}
	require.NoError(t, b.handleEventAndACK(s, gtidReplay, false))
	require.True(t, gtidReplay.Replay)

	xidReplay := &BinlogEvent{
		Header: &EventHeader{EventType: XID_EVENT, LogPos: 400, Timestamp: 2},
		Event:  &XIDEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, xidReplay, false))
	require.True(t, xidReplay.Replay, "non-GTID events must inherit the transaction replay flag")

	// New transaction GNO 5 is outside the boundary and must not be flagged.
	gtidNew := &BinlogEvent{
		Header: &EventHeader{EventType: GTID_EVENT, Timestamp: 3},
		Event:  &GTIDEvent{SID: u[:], GNO: 5},
	}
	require.NoError(t, b.handleEventAndACK(s, gtidNew, false))
	require.False(t, gtidNew.Replay)

	xidNew := &BinlogEvent{
		Header: &EventHeader{EventType: XID_EVENT, LogPos: 500, Timestamp: 3},
		Event:  &XIDEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, xidNew, false))
	require.False(t, xidNew.Replay)
}

// TestResumeCheckpointGTIDConfirmedSet checks the GTID resume point in both
// manual and automatic modes.
func TestResumeCheckpointGTIDConfirmedSet(t *testing.T) {
	b := newTestSyncer(t, true)
	confirmed, err := mysql.ParseMysqlGTIDSet("de278ad0-2106-11e4-9f8e-6edd0ca20947:1-2")
	require.NoError(t, err)
	high, err := mysql.ParseMysqlGTIDSet("de278ad0-2106-11e4-9f8e-6edd0ca20947:1-5")
	require.NoError(t, err)
	b.confirmedGset = confirmed
	b.prevGset = high

	cp := b.resumeCheckpoint()
	require.Equal(t, confirmed.String(), cp.GTIDSet.String())

	b.cfg.ManualCheckpoint = false
	cp = b.resumeCheckpoint()
	require.Equal(t, high.String(), cp.GTIDSet.String())
}

// TestIsResumePositionUnavailableClassification makes sure only the server's
// 1236 fatal binlog error is treated as a non-retryable purge; ordinary
// network errors keep going through the retry loop.
func TestIsResumePositionUnavailableClassification(t *testing.T) {
	require.False(t, isResumePositionUnavailable(nil))
	require.False(t, isResumePositionUnavailable(errors.New("connection was bad")))

	// MyError.Error() renders as "ERROR 1236 (HY000): ..." which
	// mysql.ErrorCode parses back to the numeric code.
	err1236 := mysql.NewDefaultError(mysql.ER_MASTER_FATAL_ERROR_READING_BINLOG,
		"Could not find first log file name in binary log index file")
	require.True(t, isResumePositionUnavailable(err1236))

	wrapped := &ResumePositionUnavailableError{
		Resume: Checkpoint{Position: mysql.Position{Name: "mysql-bin.000001", Pos: 4}},
		Reason: err1236,
	}
	require.True(t, isResumePositionUnavailable(wrapped))
	require.ErrorContains(t, wrapped, "manual intervention required")
}

// TestWrapResumeErrorLeavesTransientErrorsUntouched ensures only purge
// failures get the typed wrapper; other errors propagate unchanged so the
// retry loop handles them.
func TestWrapResumeErrorLeavesTransientErrorsUntouched(t *testing.T) {
	b := newTestSyncer(t, true)
	cp := Checkpoint{Position: mysql.Position{Name: "mysql-bin.000001", Pos: 4}}

	transient := errors.New("i/o timeout")
	require.Equal(t, transient, b.wrapResumeError(transient, cp))

	fatal := mysql.NewDefaultError(mysql.ER_MASTER_FATAL_ERROR_READING_BINLOG, "purged log")
	wrapped := b.wrapResumeError(fatal, cp)
	var unavailable *ResumePositionUnavailableError
	require.True(t, stderrors.As(wrapped, &unavailable))
	require.Equal(t, "mysql-bin.000001", unavailable.Resume.Position.Name)
}

// TestLagSecondsZeroBeforeEvents confirms lag reporting starts at zero and
// never produces negative values.
func TestLagSecondsZeroBeforeEvents(t *testing.T) {
	b := newTestSyncer(t, true)
	require.Equal(t, uint64(0), b.LagSeconds())

	s := NewBinlogStreamer()
	// A future-dated event (clock skew) must not underflow the lag.
	ev := &BinlogEvent{
		Header: &EventHeader{EventType: HEARTBEAT_EVENT, Timestamp: uint32(time.Now().Unix()) + 3600},
		Event:  &HeartbeatEvent{},
	}
	require.NoError(t, b.handleEventAndACK(s, ev, false))
	require.Equal(t, uint64(0), b.LagSeconds())
}
