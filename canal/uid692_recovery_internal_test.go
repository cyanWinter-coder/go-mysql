package canal

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/pingcap/tidb/pkg/parser"
	"github.com/stretchr/testify/require"
)

type uid692FlakyRowHandler struct {
	DummyEventHandler
	calls atomic.Int32
}

func (h *uid692FlakyRowHandler) OnRow(*RowsEvent) error {
	if h.calls.Add(1) == 1 {
		return errors.New("uid692 simulated bad definition")
	}
	return nil
}

func uid692InternalLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func uid692RowBinlogEvent() *replication.BinlogEvent {
	return &replication.BinlogEvent{
		RawData: []byte("uid692-raw-event"),
		Header:  &replication.EventHeader{EventType: replication.WRITE_ROWS_EVENTv2, LogPos: 4242},
		Event: &replication.RowsEvent{
			Table: &replication.TableMapEvent{
				Schema: []byte("db"),
				Table:  []byte("t"),
			},
		},
	}
}

func TestUID692CanalPreservesAndReplaysFailedEvent(t *testing.T) {
	logger := uid692InternalLogger()
	handler := &uid692FlakyRowHandler{}
	c := &Canal{
		cfg:          &Config{Logger: logger},
		master:       &masterInfo{logger: logger},
		eventHandler: handler,
	}

	def := &schema.Table{Schema: "db", Name: "t"}
	def.AddColumn("id", "int", "", "")
	c.SetTableCache([]byte("db"), []byte("t"), def)

	ev := uid692RowBinlogEvent()
	err := c.handleRowsEvent(ev)
	require.Error(t, err)
	require.EqualValues(t, 1, handler.calls.Load())

	failed := c.FailedEvent()
	require.NotNil(t, failed)
	require.Equal(t, "db.t", failed.Key)
	require.Equal(t, []byte("uid692-raw-event"), failed.Raw)
	require.Same(t, ev, failed.Binlog)

	// Repair is represented by replacing the cache; the no-argument replay
	// selects the latest unresolved event.
	repaired := &schema.Table{Schema: "db", Name: "t", Version: "fixed"}
	repaired.AddColumn("id", "int", "", "")
	repaired.AddColumn("name", "varchar(10)", "", "")
	c.SetTableCache([]byte("db"), []byte("t"), repaired)

	require.NoError(t, c.RetryFailedEvent())
	require.EqualValues(t, 2, handler.calls.Load())
	require.Nil(t, c.FailedEvent())
}

func TestUID692DDLInvalidatesMetadataGeneration(t *testing.T) {
	logger := uid692InternalLogger()
	c := &Canal{
		cfg:          &Config{Logger: logger},
		master:       &masterInfo{logger: logger},
		eventHandler: &DummyEventHandler{},
		parser:       parser.New(),
	}

	def := &schema.Table{Schema: "db", Name: "t"}
	def.AddColumn("id", "int", "", "")
	c.SetTableCache([]byte("db"), []byte("t"), def)
	version := schema.DefinitionVersion(def)

	require.Zero(t, c.TableCacheGeneration("db", "t"))
	_, ok := c.GetTableVersion("db", "t", version)
	require.True(t, ok)

	require.NoError(t, c.updateTable(&replication.EventHeader{}, "db", "t"))
	require.EqualValues(t, 1, c.TableCacheGeneration("db", "t"))

	c.tableLock.RLock()
	_, active := c.tables["db.t"]
	c.tableLock.RUnlock()
	require.False(t, active, "DDL must remove the active old definition")

	_, ok = c.GetTableVersion("db", "t", version)
	require.True(t, ok, "versioned old definition remains available for diagnosis/replay")
}

type uid692ReentrantGetHandler struct {
	DummyEventHandler
	canal *Canal
}

func (h *uid692ReentrantGetHandler) OnRow(e *RowsEvent) error {
	_, err := h.canal.GetTable(e.Table.Schema, e.Table.Name)
	return err
}

func TestUID692OnRowCanReenterGetTable(t *testing.T) {
	logger := uid692InternalLogger()
	c := &Canal{
		cfg:    &Config{Logger: logger},
		master: &masterInfo{logger: logger},
	}
	c.eventHandler = &uid692ReentrantGetHandler{canal: c}

	def := &schema.Table{Schema: "db", Name: "t"}
	def.AddColumn("id", "int", "", "")
	c.SetTableCache([]byte("db"), []byte("t"), def)

	done := make(chan error, 1)
	go func() {
		done <- c.handleRowsEvent(uid692RowBinlogEvent())
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("GetTable from OnRow deadlocked")
	}
}

func TestUID692PreservesUnparsedDDL(t *testing.T) {
	h := &unparsedQueryRecorder{}
	c := newQueryEventCanal(h)

	err := c.handleEvent(queryEvent(unparsableDDL, 120))
	require.NoError(t, err)
	require.Equal(t, []string{unparsableDDL}, h.queries)

	records := c.RawEventJournal().List()
	require.Len(t, records, 1)
	require.Equal(t, "unparsed-ddl", records[0].Kind)
	require.Contains(t, records[0].Query, "ALTER TABLE")
	require.NotNil(t, records[0].Binlog)
}

func TestUID692NilCanalCacheMethodsAreSafe(t *testing.T) {
	c := &Canal{}
	def := &schema.Table{Schema: "db", Name: "t"}
	def.AddColumn("id", "int", "", "")

	require.NotPanics(t, func() {
		c.SetTableCache([]byte("db"), []byte("t"), def)
		c.ClearTableCache([]byte("db"), []byte("t"))
		_ = c.TableCacheGeneration("db", "t")
		_ = c.RawEventJournal()
	})
}
