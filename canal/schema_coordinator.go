package canal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
)

// RawEventRecord is the preserved copy of an event that could not be parsed or
// applied with the available table definition.
//
// Raw always retains the original binlog event bytes in memory. When the journal
// has a directory, those bytes are also stored in a separate .bin file and the
// JSON record points at it, so an operator can repair the definition and replay
// the exact event.
type RawEventRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind,omitempty"`
	Schema    string    `json:"schema"`
	Table     string    `json:"table"`
	Key       string    `json:"key"`
	Position  string    `json:"position,omitempty"`
	LogPos    uint32    `json:"log_pos,omitempty"`
	EventType string    `json:"event_type,omitempty"`
	Query     string    `json:"query,omitempty"`
	RawFile   string    `json:"raw_file,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Attempts  int       `json:"attempts"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Resolved  bool      `json:"resolved,omitempty"`

	// Raw is the untouched binlog payload. It is intentionally excluded from
	// JSON metadata and persisted as a binary sidecar file.
	Raw []byte `json:"-"`

	// Binlog is the decoded event used for in-process replay. It is not
	// serialized; a process restart replays from Raw or the binlog position.
	Binlog *replication.BinlogEvent `json:"-"`
}

// FailedEventJournal stores raw events that are parked for manual recovery.
type FailedEventJournal struct {
	dir    string
	logger *slog.Logger

	mu      sync.RWMutex
	records map[string]*RawEventRecord
	order   []string
}

// NewFailedEventJournal creates an in-memory journal or, when dir is non-empty,
// a journal that also writes one JSON metadata file and one raw .bin sidecar
// per event.
func NewFailedEventJournal(dir string, logger *slog.Logger) (*FailedEventJournal, error) {
	if logger == nil {
		logger = slog.Default()
	}
	j := &FailedEventJournal{dir: dir, logger: logger, records: make(map[string]*RawEventRecord)}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
		if err := j.load(); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *FailedEventJournal) load() error {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(j.dir, entry.Name()))
		if err != nil {
			return err
		}
		var rec RawEventRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			j.logger.Error("parse failed-event record", slog.String("file", entry.Name()), slog.Any("error", err))
			continue
		}
		if rec.RawFile != "" {
			raw, err := os.ReadFile(filepath.Join(j.dir, rec.RawFile))
			if err != nil {
				j.logger.Error("read raw failed-event payload", slog.String("file", rec.RawFile), slog.Any("error", err))
			} else {
				rec.Raw = raw
			}
		}
		j.records[rec.ID] = &rec
		j.order = append(j.order, rec.ID)
	}
	return nil
}

// Save inserts or updates a record. The raw byte slice is copied so later
// binlog buffer reuse cannot mutate the preserved event.
func (j *FailedEventJournal) Save(rec *RawEventRecord) (*RawEventRecord, error) {
	if rec == nil {
		return nil, errors.New("canal: nil raw event record")
	}
	if rec.ID == "" {
		rec.ID = NewRawEventID(rec.Key, rec.Position, rec.LogPos, rec.EventType, rec.Attempts)
	}
	if rec.Key == "" {
		rec.Key = schema.TableKey(rec.Schema, rec.Table)
	}
	now := time.Now()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	if rec.Raw != nil {
		rec.Raw = append([]byte(nil), rec.Raw...)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if old, ok := j.records[rec.ID]; ok {
		rec.CreatedAt = old.CreatedAt
		j.records[rec.ID] = rec
	} else {
		j.records[rec.ID] = rec
		j.order = append(j.order, rec.ID)
	}

	if j.dir == "" {
		return rec, nil
	}

	if len(rec.Raw) > 0 {
		rawName := rec.ID + ".bin"
		if err := os.WriteFile(filepath.Join(j.dir, rawName), rec.Raw, 0o600); err != nil {
			return rec, err
		}
		rec.RawFile = rawName
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return rec, err
	}
	if err := os.WriteFile(filepath.Join(j.dir, rec.ID+".json"), data, 0o600); err != nil {
		return rec, err
	}
	return rec, nil
}

// Get returns a copy of a record and its raw bytes.
func (j *FailedEventJournal) Get(id string) (*RawEventRecord, bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	rec, ok := j.records[id]
	if !ok {
		return nil, false
	}
	return cloneRawEventRecord(rec), true
}

// List returns all records in save order.
func (j *FailedEventJournal) List() []*RawEventRecord {
	j.mu.RLock()
	defer j.mu.RUnlock()
	out := make([]*RawEventRecord, 0, len(j.order))
	for _, id := range j.order {
		if rec, ok := j.records[id]; ok {
			out = append(out, cloneRawEventRecord(rec))
		}
	}
	return out
}

// Failed returns unresolved parked records.
func (j *FailedEventJournal) Failed() []*RawEventRecord {
	all := j.List()
	out := make([]*RawEventRecord, 0, len(all))
	for _, rec := range all {
		if !rec.Resolved {
			out = append(out, rec)
		}
	}
	return out
}

// Resolve marks a record as successfully replayed but retains it for audit.
func (j *FailedEventJournal) Resolve(id string) error {
	j.mu.Lock()
	rec, ok := j.records[id]
	if !ok {
		j.mu.Unlock()
		return fmt.Errorf("canal: unknown raw event %q", id)
	}
	rec.Resolved = true
	rec.UpdatedAt = time.Now()
	j.mu.Unlock()

	if j.dir != "" {
		_, err := j.Save(rec)
		return err
	}
	return nil
}

// Delete removes a record and its persisted files.
func (j *FailedEventJournal) Delete(id string) error {
	j.mu.Lock()
	rec, ok := j.records[id]
	if ok {
		delete(j.records, id)
	}
	j.mu.Unlock()
	if !ok {
		return fmt.Errorf("canal: unknown raw event %q", id)
	}
	if j.dir == "" {
		return nil
	}
	_ = os.Remove(filepath.Join(j.dir, id+".json"))
	if rec.RawFile != "" {
		return os.Remove(filepath.Join(j.dir, rec.RawFile))
	}
	return nil
}

func cloneRawEventRecord(rec *RawEventRecord) *RawEventRecord {
	cp := *rec
	if rec.Raw != nil {
		cp.Raw = append([]byte(nil), rec.Raw...)
	}
	return &cp
}

// NewRawEventID derives a stable ID from an event's coordinates.
func NewRawEventID(key, position string, logPos uint32, eventType string, extra any) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%s|%v", key, position, logPos, eventType, extra)
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// ErrCoordinatorClosed is returned when an event is submitted after Close.
var ErrCoordinatorClosed = errors.New("canal: schema coordinator is closed")

// EventEnvelope is one table-scoped event handled by SchemaCoordinator.
type EventEnvelope struct {
	ID       string
	Schema   string
	Table    string
	Position mysql.Position

	// Binlog is preferred for normal Canal replay.
	Binlog *replication.BinlogEvent

	// Raw may be set without a decoded Binlog event. If empty, Binlog.RawData
	// is preserved.
	Raw []byte

	// Kind/Query describe non-row events such as an unparsed DDL.
	Kind  string
	Query string

	done chan error
}

func (e EventEnvelope) key() string {
	return schema.TableKey(e.Schema, e.Table)
}

func (e EventEnvelope) rawBytes() []byte {
	if len(e.Raw) > 0 {
		return e.Raw
	}
	if e.Binlog != nil {
		return e.Binlog.RawData
	}
	return nil
}

func (e EventEnvelope) eventType() string {
	if e.Binlog != nil && e.Binlog.Header != nil {
		return e.Binlog.Header.EventType.String()
	}
	return e.Kind
}

// DefinitionSource pins one active definition for the duration of fn.
// *schema.TableCache and *Canal both implement this contract.
type DefinitionSource interface {
	Resolve(ctx context.Context, schemaName, tableName string, fn func(*schema.VersionedTable) error) error
}

// RowEventHandler applies one event using a definition pinned for the call.
type RowEventHandler func(context.Context, *replication.BinlogEvent, *schema.Table) error

// SchemaCoordinator serializes events per table while allowing different tables
// to make independent progress. A failed schema rebuild parks only the event
// at the head of that table's queue and retries it until the definition is
// repaired; later events for the same table wait behind it.
type SchemaCoordinator struct {
	source  DefinitionSource
	handle  RowEventHandler
	journal *FailedEventJournal
	logger  *slog.Logger

	backoff func(attempt int) time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	workers map[string]*tableEventWorker
	closed  bool
}

// CoordinatorOption configures a SchemaCoordinator.
type CoordinatorOption func(*SchemaCoordinator)

// WithCoordinatorJournal sets the raw failed-event journal.
func WithCoordinatorJournal(journal *FailedEventJournal) CoordinatorOption {
	return func(c *SchemaCoordinator) { c.journal = journal }
}

// WithCoordinatorLogger sets the coordinator logger.
func WithCoordinatorLogger(logger *slog.Logger) CoordinatorOption {
	return func(c *SchemaCoordinator) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithRetryBackoff sets the delay between rebuild/replay attempts.
func WithRetryBackoff(backoff func(attempt int) time.Duration) CoordinatorOption {
	return func(c *SchemaCoordinator) {
		if backoff != nil {
			c.backoff = backoff
		}
	}
}

type tableEventWorker struct {
	queue  []EventEnvelope
	notify chan struct{}
	wake   chan struct{}

	mu     sync.Mutex
	parked *RawEventRecord
}

// NewSchemaCoordinator creates a coordinator. source loads and pins table
// definitions; handle is called while the per-table definition lock is held.
func NewSchemaCoordinator(source DefinitionSource, handle RowEventHandler, opts ...CoordinatorOption) *SchemaCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	c := &SchemaCoordinator{
		source:  source,
		handle:  handle,
		logger:  slog.Default(),
		backoff: coordinatorDefaultBackoff,
		ctx:     ctx,
		cancel:  cancel,
		workers: make(map[string]*tableEventWorker),
	}
	if c.journal == nil {
		j, _ := NewFailedEventJournal("", c.logger)
		c.journal = j
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func coordinatorDefaultBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return time.Second
	}
	d := time.Duration(1<<min(attempt-1, 6)) * time.Second
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

// NewRowEventCoordinator creates a coordinator that delivers Canal row events
// through the currently registered EventHandler.
func (c *Canal) NewRowEventCoordinator(opts ...CoordinatorOption) *SchemaCoordinator {
	handler := func(_ context.Context, binlogEvent *replication.BinlogEvent, table *schema.Table) error {
		if binlogEvent == nil || binlogEvent.Header == nil {
			return errors.New("canal: coordinator received an event without binlog header")
		}
		rowsEvent, ok := binlogEvent.Event.(*replication.RowsEvent)
		if !ok {
			return fmt.Errorf("canal: coordinator expected *replication.RowsEvent, got %T", binlogEvent.Event)
		}
		action, err := rowActionForType(binlogEvent.Header.EventType)
		if err != nil {
			return err
		}
		return c.eventHandler.OnRow(newRowsEvent(table, action, rowsEvent.Rows, binlogEvent.Header, rowsEvent))
	}

	defaults := []CoordinatorOption{
		WithCoordinatorLogger(c.baseLogger()),
		WithCoordinatorJournal(c.RawEventJournal()),
	}
	return NewSchemaCoordinator(c, handler, append(defaults, opts...)...)
}

// Journal returns the raw event journal.
func (c *SchemaCoordinator) Journal() *FailedEventJournal { return c.journal }

// FailedEvents returns all currently parked events.
func (c *SchemaCoordinator) FailedEvents() []*RawEventRecord { return c.journal.Failed() }

func (c *SchemaCoordinator) worker(key, schemaName, tableName string) (*tableEventWorker, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrCoordinatorClosed
	}
	w, ok := c.workers[key]
	if !ok {
		w = &tableEventWorker{
			notify: make(chan struct{}, 1),
			wake:   make(chan struct{}, 1),
		}
		c.workers[key] = w
		c.wg.Add(1)
		go c.runWorker(schemaName, tableName, w)
	}
	return w, nil
}

// Dispatch enqueues an event and returns once it is queued.
func (c *SchemaCoordinator) Dispatch(ev EventEnvelope) error {
	if c.source == nil {
		return errors.New("canal: schema coordinator requires a definition source")
	}
	key := ev.key()
	if key == "." {
		return errors.New("canal: event envelope requires schema and table")
	}
	w, err := c.worker(key, ev.Schema, ev.Table)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.queue = append(w.queue, ev)
	w.mu.Unlock()

	select {
	case w.notify <- struct{}{}:
	default:
	}
	return nil
}

// Execute enqueues an event and waits for its terminal processing result or ctx
// cancellation. A canceled caller does not remove the event: the coordinator
// continues parked recovery unless Close is called.
func (c *SchemaCoordinator) Execute(ctx context.Context, ev EventEnvelope) error {
	done := make(chan error, 1)
	ev.done = done
	if err := c.Dispatch(ev); err != nil {
		return err
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

// RetryEvent wakes the worker parked on id. The definition should be repaired
// first, for example through Cache().Put.
func (c *SchemaCoordinator) RetryEvent(id string) error {
	rec, ok := c.journal.Get(id)
	if !ok {
		return fmt.Errorf("canal: unknown failed event %q", id)
	}

	c.mu.Lock()
	w, ok := c.workers[rec.Key]
	c.mu.Unlock()
	if ok {
		select {
		case w.wake <- struct{}{}:
		default:
		}
		return nil
	}

	// No live worker (for example after restart): re-enqueue the preserved
	// in-process decoded event when available. Raw-only records need a binlog
	// replay component to reconstruct the event from Raw/Position.
	return c.Dispatch(EventEnvelope{
		ID:       rec.ID,
		Schema:   rec.Schema,
		Table:    rec.Table,
		Position: mysql.Position{Name: rec.Position},
		Binlog:   rec.Binlog,
		Raw:      rec.Raw,
		Kind:     rec.Kind,
		Query:    rec.Query,
	})
}

// ReplayEvent is an alias for RetryEvent.
func (c *SchemaCoordinator) ReplayEvent(id string) error { return c.RetryEvent(id) }

// Source returns the definition source used by the coordinator.
func (c *SchemaCoordinator) Source() DefinitionSource { return c.source }

// Cache returns the versioned cache when the coordinator was constructed with
// a *schema.TableCache; otherwise it returns nil.
func (c *SchemaCoordinator) Cache() *schema.TableCache {
	cache, _ := c.source.(*schema.TableCache)
	return cache
}

// Close stops all table workers. Parked raw events remain in the journal.
func (c *SchemaCoordinator) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	c.wg.Wait()
}

func (c *SchemaCoordinator) runWorker(schemaName, tableName string, w *tableEventWorker) {
	defer c.wg.Done()

	for {
		ev, err := c.popEnvelope(w)
		if err != nil {
			return
		}
		result := c.processEvent(schemaName, tableName, w, ev)
		if ev.done != nil {
			select {
			case ev.done <- result:
			default:
			}
		}
	}
}

func (c *SchemaCoordinator) popEnvelope(w *tableEventWorker) (EventEnvelope, error) {
	for {
		w.mu.Lock()
		if len(w.queue) > 0 {
			ev := w.queue[0]
			w.queue = w.queue[1:]
			w.mu.Unlock()
			return ev, nil
		}
		w.mu.Unlock()

		select {
		case <-w.notify:
		case <-c.ctx.Done():
			return EventEnvelope{}, c.ctx.Err()
		}
	}
}

func (c *SchemaCoordinator) processEvent(schemaName, tableName string, w *tableEventWorker, ev EventEnvelope) error {
	attempt := 0
	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}

		var processErr error
		err := c.source.Resolve(c.ctx, schemaName, tableName, func(vt *schema.VersionedTable) error {
			if c.handle == nil || vt == nil {
				return nil
			}
			return c.handle(c.ctx, ev.Binlog, vt.Table)
		})
		if err == nil {
			if parked := w.getParked(); parked != nil {
				if resolveErr := c.journal.Resolve(parked.ID); resolveErr != nil {
					c.logger.Error("resolve recovered event record", slog.Any("error", resolveErr))
				}
				w.setParked(nil)
			}
			return nil
		}
		processErr = err

		attempt++
		rec := c.recordForEnvelope(ev, processErr, attempt)
		saved, saveErr := c.journal.Save(rec)
		if saveErr != nil {
			c.logger.Error("preserve raw event failed", slog.Any("error", saveErr))
		} else {
			rec = saved
		}
		w.setParked(rec)

		c.logger.Error("table schema recovery failed; event is parked and will be replayed",
			slog.String("event_id", rec.ID),
			slog.String("key", rec.Key),
			slog.String("position", rec.Position),
			slog.Uint64("log_pos", uint64(rec.LogPos)),
			slog.Int("attempt", attempt),
			slog.Any("error", processErr),
		)

		delay := c.backoff(attempt)
		timer := time.NewTimer(delay)
		select {
		case <-w.wake:
			timer.Stop()
			c.logger.Info("retrying parked table event after explicit wake", slog.String("event_id", rec.ID), slog.String("key", rec.Key))
		case <-timer.C:
		case <-c.ctx.Done():
			timer.Stop()
			return c.ctx.Err()
		}
	}
}

func (c *SchemaCoordinator) recordForEnvelope(ev EventEnvelope, err error, attempt int) *RawEventRecord {
	position := ev.Position.Name
	logPos := ev.Position.Pos
	if ev.Binlog != nil && ev.Binlog.Header != nil {
		if logPos == 0 {
			logPos = ev.Binlog.Header.LogPos
		}
		if position == "" {
			position = fmt.Sprintf("header-log-pos:%d", ev.Binlog.Header.LogPos)
		}
	}
	if position == "" {
		position = ev.Position.String()
	}
	id := ev.ID
	if id == "" {
		id = NewRawEventID(ev.key(), position, logPos, ev.eventType(), len(ev.rawBytes()))
	}
	return &RawEventRecord{
		ID:        id,
		Kind:      ev.Kind,
		Schema:    ev.Schema,
		Table:     ev.Table,
		Key:       ev.key(),
		Position:  position,
		LogPos:    logPos,
		EventType: ev.eventType(),
		Query:     ev.Query,
		Raw:       ev.rawBytes(),
		Binlog:    ev.Binlog,
		LastError: err.Error(),
		Attempts:  attempt,
	}
}

func (w *tableEventWorker) setParked(rec *RawEventRecord) {
	w.mu.Lock()
	w.parked = rec
	w.mu.Unlock()
}

func (w *tableEventWorker) getParked() *RawEventRecord {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.parked
}
