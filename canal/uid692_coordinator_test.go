package canal_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/canal"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/stretchr/testify/require"
)

type uid692RecordedEvent struct {
	table   string
	raw     string
	version any
}

type uid692RecordingHandler struct {
	mu      sync.Mutex
	events  []uid692RecordedEvent
	started chan struct{}
}

func newUID692RecordingHandler() *uid692RecordingHandler {
	return &uid692RecordingHandler{started: make(chan struct{}, 16)}
}

func (h *uid692RecordingHandler) handle(_ context.Context, e *replication.BinlogEvent, table *schema.Table) error {
	raw := ""
	if e != nil {
		raw = string(e.RawData)
	}
	h.mu.Lock()
	h.events = append(h.events, uid692RecordedEvent{table: table.Name, raw: raw, version: table.Version})
	h.mu.Unlock()
	h.started <- struct{}{}
	return nil
}

func (h *uid692RecordingHandler) snapshot() []uid692RecordedEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uid692RecordedEvent(nil), h.events...)
}

func uid692DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func uid692Envelope(db, table, raw string) canal.EventEnvelope {
	return canal.EventEnvelope{
		Schema: db,
		Table:  table,
		Raw:    []byte(raw),
		Binlog: &replication.BinlogEvent{
			RawData: []byte(raw),
			Header:  &replication.EventHeader{EventType: replication.WRITE_ROWS_EVENTv2},
		},
	}
}

func TestUID692CoordinatorParksOneTableAndOtherTablesContinue(t *testing.T) {
	logger := uid692DiscardLogger()
	var failA uid692AtomicBool
	failA.store(true)

	cache := schema.NewTableCache(schema.TableLoaderFunc(func(_ context.Context, db, table string) (*schema.VersionedTable, error) {
		if db == "db" && table == "a" && failA.load() {
			return nil, errors.New("schema rebuild failed")
		}
		cols := []string{"id"}
		version := "good"
		if table == "a" {
			cols = []string{"id", "name"}
			version = "a2"
		}
		def := &schema.Table{Schema: db, Name: table, Version: version}
		for _, col := range cols {
			def.AddColumn(col, "int", "", "")
		}
		return &schema.VersionedTable{Table: def, Version: version}, nil
	}), schema.WithTableCacheLogger(logger))

	handler := newUID692RecordingHandler()
	coord := canal.NewSchemaCoordinator(cache, handler.handle,
		canal.WithCoordinatorLogger(logger),
		canal.WithRetryBackoff(func(int) time.Duration { return 0 }),
	)
	defer coord.Close()

	require.NoError(t, coord.Dispatch(uid692Envelope("db", "a", "a1")))

	require.Eventually(t, func() bool {
		return len(coord.FailedEvents()) == 1
	}, time.Second, time.Millisecond)
	failed := coord.FailedEvents()[0]
	require.Equal(t, "db.a", failed.Key)
	require.Equal(t, []byte("a1"), failed.Raw)

	// A2 queues behind the parked A1 and must not be parsed/applied.
	require.NoError(t, coord.Dispatch(uid692Envelope("db", "a", "a2")))
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, handler.snapshot())

	// Other tables continue through their independent per-table worker.
	require.NoError(t, coord.Execute(context.Background(), uid692Envelope("db", "b", "b1")))
	require.NoError(t, coord.Execute(context.Background(), uid692Envelope("db", "b", "b2")))
	require.Eventually(t, func() bool { return len(handler.snapshot()) == 2 }, time.Second, time.Millisecond)
	for _, ev := range handler.snapshot() {
		require.Equal(t, "b", ev.table)
	}

	// Operator repairs the definition by versioned cache insertion, then wakes
	// the exact parked event. It and the queued event are replayed in order.
	repaired := &schema.Table{Schema: "db", Name: "a", Version: "manual-v2"}
	repaired.AddColumn("id", "int", "", "")
	repaired.AddColumn("name", "varchar(32)", "", "")
	cache.Put(&schema.VersionedTable{Table: repaired, Version: "manual-v2"})
	require.NoError(t, coord.RetryEvent(failed.ID))

	require.Eventually(t, func() bool { return len(handler.snapshot()) == 4 }, time.Second, time.Millisecond)
	events := handler.snapshot()
	require.Equal(t, []string{"b1", "b2", "a1", "a2"}, []string{events[0].raw, events[1].raw, events[2].raw, events[3].raw})
	for _, ev := range events[2:] {
		require.Equal(t, "manual-v2", ev.version, "both events for a must use the same switched definition")
	}
	require.Eventually(t, func() bool { return len(coord.FailedEvents()) == 0 }, time.Second, time.Millisecond)
}

func TestUID692CoordinatorSerializesSameTable(t *testing.T) {
	cache := schema.NewTableCache(schema.TableLoaderFunc(func(context.Context, string, string) (*schema.VersionedTable, error) {
		def := &schema.Table{Schema: "db", Name: "t", Version: "v"}
		def.AddColumn("id", "int", "", "")
		return &schema.VersionedTable{Table: def, Version: "v"}, nil
	}), schema.WithTableCacheLogger(uid692DiscardLogger()))

	var mu sync.Mutex
	var active int
	var maxActive int
	var order []string
	coord := canal.NewSchemaCoordinator(cache, func(_ context.Context, e *replication.BinlogEvent, _ *schema.Table) error {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		order = append(order, string(e.RawData))
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		return nil
	}, canal.WithCoordinatorLogger(uid692DiscardLogger()))
	defer coord.Close()

	for i := range 20 {
		raw := string(rune('a' + i))
		require.NoError(t, coord.Dispatch(uid692Envelope("db", "t", raw)))
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 20
	}, 2*time.Second, 5*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, maxActive)
	require.Len(t, order, 20)
}

func TestUID692CoordinatorRejectsDispatchAfterClose(t *testing.T) {
	cache := schema.NewTableCache(nil)
	coord := canal.NewSchemaCoordinator(cache, nil, canal.WithCoordinatorLogger(uid692DiscardLogger()))
	coord.Close()
	coord.Close()
	err := coord.Dispatch(uid692Envelope("db", "t", "x"))
	require.ErrorIs(t, err, canal.ErrCoordinatorClosed)
}

func TestUID692KeyedExecutorCrossTableParallel(t *testing.T) {
	exec := canal.NewKeyedExecutor()
	aEntered := make(chan struct{})
	releaseA := make(chan struct{})
	bDone := make(chan struct{})

	go func() {
		_ = exec.Do("a", func() error {
			close(aEntered)
			<-releaseA
			return nil
		})
	}()
	<-aEntered

	go func() {
		_ = exec.Do("b", func() error { return nil })
		close(bDone)
	}()
	select {
	case <-bDone:
	case <-time.After(time.Second):
		t.Fatal("key a blocked key b")
	}

	sameKeyDone := make(chan struct{})
	go func() {
		_ = exec.Do("a", func() error { return nil })
		close(sameKeyDone)
	}()
	select {
	case <-sameKeyDone:
		t.Fatal("second event for same table ran concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseA)
	<-sameKeyDone
}

type uid692AtomicBool struct{ v sync.Map }

func (a *uid692AtomicBool) store(v bool) { a.v.Store("v", v) }
func (a *uid692AtomicBool) load() bool {
	v, _ := a.v.Load("v")
	b, _ := v.(bool)
	return b
}
