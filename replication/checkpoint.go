package replication

import (
	"fmt"

	"github.com/go-mysql-org/go-mysql/mysql"
)

// Checkpoint is an explicit, durable resume position. It carries the binlog
// file/offset used by non-GTID replication and, when GTIDs are in use, the
// GTID set acknowledged by the downstream.
//
// The syncer distinguishes two kinds of position:
//   - the read high-water mark: the furthest position it has parsed from the
//     network stream (GetNextPosition / the internal prevGset). Events up to
//     this point may still be queued and not applied downstream, so it is not
//     safe to resume from it after a crash.
//   - the confirmed checkpoint: a position the downstream has applied and made
//     durable, typically inside the same transaction that wrote the event
//     data. Reconnect always resumes from the confirmed checkpoint; events
//     past it may be replayed and are flagged on the BinlogEvent so the
//     downstream can deduplicate them.
type Checkpoint struct {
	// Position is the binlog filename and next offset. The zero Position
	// (empty Name) means no file/offset has been confirmed yet.
	Position mysql.Position

	// GTIDSet is the confirmed GTID set. It is nil for file/position based
	// replication or before the first GTID event has been confirmed.
	GTIDSet mysql.GTIDSet
}

// String renders the checkpoint for logging. It never panics on a nil GTID
// set.
func (c Checkpoint) String() string {
	if c.GTIDSet != nil {
		return fmt.Sprintf("position=%s gtid_set=%s", c.Position, c.GTIDSet.String())
	}
	return fmt.Sprintf("position=%s", c.Position)
}

// IsZero reports whether neither a file position nor a GTID set has been
// confirmed.
func (c Checkpoint) IsZero() bool {
	return c.Position.Name == "" && c.GTIDSet == nil
}

// ResumePositionUnavailableError means the server can no longer serve binlog
// from the confirmed checkpoint: the required binlog file has been purged
// (server error 1236) or is absent from SHOW BINARY LOGS. Retrying the same
// position can never succeed, so the syncer stops the retry loop and closes
// the stream with this error instead of silently resuming from the newest
// binlog. An operator must confirm a new, valid start position and restart the
// syncer explicitly.
type ResumePositionUnavailableError struct {
	// Resume is the checkpoint the syncer tried, and failed, to resume from.
	Resume Checkpoint

	// Reason is the underlying server error or the range-check failure.
	Reason error
}

func (e *ResumePositionUnavailableError) Error() string {
	return fmt.Sprintf("resume position is no longer available on the server, "+
		"manual intervention required to pick a new start position (%s): %v",
		e.Resume.String(), e.Reason)
}

func (e *ResumePositionUnavailableError) Unwrap() error {
	return e.Reason
}

// isResumePositionUnavailable reports whether err is (or wraps) a server
// ER_MASTER_FATAL_ERROR_READING_BINLOG (1236). That code is returned for a
// purged or unknown binlog file/GTID when COM_BINLOG_DUMP starts, and also as
// an ERR packet on the stream while dumping.
func isResumePositionUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*ResumePositionUnavailableError); ok {
		return true
	}
	return mysql.ErrorCode(err.Error()) == mysql.ER_MASTER_FATAL_ERROR_READING_BINLOG
}
