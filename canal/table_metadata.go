package canal

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/pingcap/errors"
)

type tableMetadataState struct {
	mu sync.Mutex

	// versions retains definitions by their version key even after active
	// invalidation, allowing an older event to be diagnosed/replayed and making
	// repeated requests for the same version cache hits.
	versions          map[string]*schema.Table
	currentVersionKey string
	generation        uint64
}

func (c *Canal) metadataState(key string) *tableMetadataState {
	c.tableLock.Lock()
	defer c.tableLock.Unlock()

	if c.tableStates == nil {
		c.tableStates = make(map[string]*tableMetadataState)
	}
	state, ok := c.tableStates[key]
	if !ok {
		state = &tableMetadataState{versions: make(map[string]*schema.Table)}
		c.tableStates[key] = state
	}
	return state
}

func (c *Canal) baseLogger() *slog.Logger {
	if c.cfg != nil && c.cfg.Logger != nil {
		return c.cfg.Logger
	}
	return slog.Default()
}

func (c *Canal) operationContext() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *Canal) safeMasterPosition() mysql.Position {
	if c.master == nil {
		return mysql.Position{}
	}
	return c.master.Position()
}

// GetTable returns the active table definition, rebuilding it if the cache was
// invalidated. Concurrent calls for the same table share one rebuild; rebuilds
// for different tables use independent locks.
func (c *Canal) GetTable(db string, table string) (*schema.Table, error) {
	key := fmt.Sprintf("%s.%s", db, table)
	// if table is excluded, return error and skip parsing event or dump
	if !c.checkTableMatch(key) {
		return nil, ErrExcludedTable
	}

	state := c.metadataState(key)
	state.mu.Lock()
	defer state.mu.Unlock()

	return c.getTableLocked(db, table, key, state)
}

func (c *Canal) tableEventExecutor() *KeyedExecutor {
	c.tableLock.Lock()
	defer c.tableLock.Unlock()
	if c.tableExecutor == nil {
		c.tableExecutor = NewKeyedExecutor()
	}
	return c.tableExecutor
}

// Resolve implements the DefinitionSource contract used by SchemaCoordinator.
// Events for one table are serialized; metadata locks are not held across the
// user callback, so EventHandler.OnRow may safely call GetTable again.
func (c *Canal) Resolve(ctx context.Context, db, table string, fn func(*schema.VersionedTable) error) error {
	_ = ctx // Canal metadata fetch uses c.ctx and the shared connection lock.
	key := schema.TableKey(db, table)
	return c.tableEventExecutor().Do(key, func() error {
		t, err := c.GetTable(db, table)
		if err != nil {
			return err
		}
		return fn(&schema.VersionedTable{Table: t, Version: effectiveTableVersion(t)})
	})
}

func (c *Canal) getTableLocked(db, table, key string, state *tableMetadataState) (*schema.Table, error) {
	c.tableLock.RLock()
	t, ok := c.tables[key]
	c.tableLock.RUnlock()
	if ok && t != nil {
		c.rememberTableVersionLocked(state, t)
		return t, nil
	}

	if c.cfg != nil && c.cfg.DiscardNoMetaRowEvent {
		c.tableLock.RLock()
		lastTime, ok := c.errorTablesGetTime[key]
		c.tableLock.RUnlock()
		if ok && time.Since(lastTime) < UnknownTableRetryPeriod {
			return nil, schema.ErrMissingTableMeta
		}
	}

	t, err := schema.NewTable(c, db, table)
	if err != nil {
		// check table not exists
		if ok, err1 := schema.IsTableExist(c, db, table); err1 == nil && !ok {
			return nil, schema.ErrTableNotExist
		}
		// work around : RDS HAHeartBeat
		// ref : https://github.com/alibaba/canal/blob/master/parse/src/main/java/com/alibaba/otter/canal/parse/inbound/mysql/dbsync/LogEventConvert.java#L385
		// issue : https://github.com/alibaba/canal/issues/222
		// This is a common error in RDS that canal can't get HAHealthCheckSchema's meta, so we mock a table meta.
		// If canal just skip and log error, as RDS HA heartbeat interval is very short, so too many HAHeartBeat errors will be logged.
		if key == schema.HAHealthCheckSchema {
			// mock ha_health_check meta
			ta := &schema.Table{
				Schema:  db,
				Name:    table,
				Columns: make([]schema.TableColumn, 0, 2),
				Indexes: make([]*schema.Index, 0),
			}
			ta.AddColumn("id", "bigint(20)", "", "")
			ta.AddColumn("type", "char(1)", "", "")
			c.storeTableLocked(key, state, ta, nil, "ha-heartbeat")
			return ta, nil
		}
		// if DiscardNoMetaRowEvent is true, we just log this error
		if c.cfg != nil && c.cfg.DiscardNoMetaRowEvent {
			c.rememberTableError(key)
			c.baseLogger().Error("canal get table meta err", slog.Any("error", errors.Trace(err)))
			return nil, schema.ErrMissingTableMeta
		}
		return nil, err
	}

	c.storeTableLocked(key, state, t, t.Version, "rebuild")
	return t, nil
}

func (c *Canal) rememberTableError(key string) {
	c.tableLock.Lock()
	defer c.tableLock.Unlock()
	if c.errorTablesGetTime == nil {
		c.errorTablesGetTime = make(map[string]time.Time)
	}
	c.errorTablesGetTime[key] = utils.Now()
}

func (c *Canal) rememberTableVersionLocked(state *tableMetadataState, t *schema.Table) string {
	version := t.Version
	if version == nil || version == "" {
		version = schema.DefinitionVersion(t)
	}
	vk := schema.VersionKey(version)
	if state.versions == nil {
		state.versions = make(map[string]*schema.Table)
	}
	state.versions[vk] = t
	if state.currentVersionKey == "" {
		state.currentVersionKey = vk
	}
	return vk
}

func (c *Canal) storeTableLocked(key string, state *tableMetadataState, t *schema.Table, version schema.TableVersion, reason string) {
	if version == nil || version == "" {
		version = t.Version
	}
	if version == nil || version == "" {
		version = schema.DefinitionVersion(t)
	}
	vk := schema.VersionKey(version)

	var fromVersion any
	if state.currentVersionKey != "" {
		if old := state.versions[state.currentVersionKey]; old != nil {
			fromVersion = effectiveTableVersion(old)
		}
	}

	if state.versions == nil {
		state.versions = make(map[string]*schema.Table)
	}
	state.versions[vk] = t
	state.currentVersionKey = vk

	c.tableLock.Lock()
	if c.tables == nil {
		c.tables = make(map[string]*schema.Table)
	}
	c.tables[key] = t
	if c.cfg != nil && c.cfg.DiscardNoMetaRowEvent {
		delete(c.errorTablesGetTime, key)
	}
	c.tableLock.Unlock()

	c.baseLogger().Info(schema.SwitchLogMessage,
		slog.String("key", key),
		slog.Any("from_version", fromVersion),
		slog.Any("to_version", version),
		slog.Uint64("generation", state.generation),
		slog.Any("binlog_position", c.safeMasterPosition()),
		slog.String("reason", reason),
	)
}

func effectiveTableVersion(t *schema.Table) any {
	if t == nil {
		return nil
	}
	if t.Version != nil && t.Version != "" {
		return t.Version
	}
	return schema.DefinitionVersion(t)
}

// GetTableVersion returns a definition cached for an explicit table version.
// It never fetches: call GetTable first to rebuild/populate the active version.
func (c *Canal) GetTableVersion(db, table string, version schema.TableVersion) (*schema.Table, bool) {
	key := fmt.Sprintf("%s.%s", db, table)
	state := c.metadataState(key)
	vk := schema.VersionKey(version)

	state.mu.Lock()
	defer state.mu.Unlock()
	t, ok := state.versions[vk]
	return t, ok
}

// ClearTableCache invalidates the active definition for a table. Versioned
// definitions already rebuilt remain available to GetTableVersion, but the next
// GetTable/row event rebuilds the active definition.
func (c *Canal) ClearTableCache(db []byte, table []byte) {
	key := fmt.Sprintf("%s.%s", db, table)
	state := c.metadataState(key)

	state.mu.Lock()
	state.generation++
	state.currentVersionKey = ""
	state.mu.Unlock()

	c.tableLock.Lock()
	delete(c.tables, key)
	if c.cfg != nil && c.cfg.DiscardNoMetaRowEvent {
		delete(c.errorTablesGetTime, key)
	}
	c.tableLock.Unlock()
}

// SetTableCache sets table cache value for the given table.
func (c *Canal) SetTableCache(db []byte, table []byte, definition *schema.Table) {
	if definition == nil {
		return
	}
	key := fmt.Sprintf("%s.%s", db, table)
	state := c.metadataState(key)

	state.mu.Lock()
	defer state.mu.Unlock()
	c.storeTableLocked(key, state, definition, definition.Version, "set")
}

// SetTableCacheVersion stores a definition under an explicit table version and
// makes it active.
func (c *Canal) SetTableCacheVersion(db, table []byte, version schema.TableVersion, definition *schema.Table) {
	if definition == nil {
		return
	}
	key := fmt.Sprintf("%s.%s", db, table)
	state := c.metadataState(key)

	state.mu.Lock()
	defer state.mu.Unlock()
	c.storeTableLocked(key, state, definition, version, "set-version")
}

// TableCacheGeneration returns the invalidation generation for a table.
func (c *Canal) TableCacheGeneration(db, table string) uint64 {
	state := c.metadataState(fmt.Sprintf("%s.%s", db, table))
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.generation
}

// FailedEvents returns raw events parked because schema rebuild or parsing did
// not succeed.
func (c *Canal) FailedEvents() []*RawEventRecord {
	if c.failedEvents == nil {
		return nil
	}
	return c.failedEvents.Failed()
}

// RawEventJournal returns the journal retaining raw failed events.
func (c *Canal) RawEventJournal() *FailedEventJournal {
	c.failedOnce.Do(func() {
		if c.failedEvents == nil {
			c.failedEvents, _ = NewFailedEventJournal("", c.baseLogger())
		}
	})
	return c.failedEvents
}

// RetryFailedEvent replays a preserved event.
//
// Arguments are intentionally variadic to support the common call shapes:
// RetryFailedEvent(), RetryFailedEvent(eventID), RetryFailedEvent(ctx, eventID),
// or RetryFailedEvent(tableKey). With no argument it retries the latest
// unresolved event.
func (c *Canal) RetryFailedEvent(args ...any) error {
	rec, err := c.resolveFailedEventArg(args)
	if err != nil {
		return err
	}
	if rec.Binlog == nil {
		return fmt.Errorf("canal: failed event %q has only raw bytes; reconstruct it with the binlog parser before replay", rec.ID)
	}
	if err := c.handleEvent(rec.Binlog); err != nil {
		return err
	}
	return c.RawEventJournal().Resolve(rec.ID)
}

// ReplayFailedEvent is an alias for RetryFailedEvent.
func (c *Canal) ReplayFailedEvent(args ...any) error {
	return c.RetryFailedEvent(args...)
}

// RetryFailedEventRecord behaves like RetryFailedEvent but returns the record
// that was selected for replay.
func (c *Canal) RetryFailedEventRecord(args ...any) (*RawEventRecord, error) {
	rec, err := c.resolveFailedEventArg(args)
	if err != nil {
		return nil, err
	}
	if err := c.RetryFailedEvent(rec.ID); err != nil {
		return rec, err
	}
	resolved, _ := c.RawEventJournal().Get(rec.ID)
	return resolved, nil
}

// FailedEvent returns the latest unresolved parked event.
func (c *Canal) FailedEvent() *RawEventRecord {
	failed := c.FailedEvents()
	if len(failed) == 0 {
		return nil
	}
	return failed[len(failed)-1]
}

// GetFailedEvent is an alias for FailedEvent.
func (c *Canal) GetFailedEvent() *RawEventRecord { return c.FailedEvent() }

// LastFailedEvent is an alias for FailedEvent.
func (c *Canal) LastFailedEvent() *RawEventRecord { return c.FailedEvent() }

// ClearFailedEvent removes one or more preserved events by ID. With no IDs it
// clears the latest unresolved event.
func (c *Canal) ClearFailedEvent(ids ...string) error {
	j := c.RawEventJournal()
	if len(ids) == 0 {
		if rec := c.FailedEvent(); rec != nil {
			ids = []string{rec.ID}
		}
	}
	for _, id := range ids {
		if err := j.Delete(id); err != nil {
			return err
		}
	}
	return nil
}

func (c *Canal) resolveFailedEventArg(args []any) (*RawEventRecord, error) {
	j := c.RawEventJournal()
	var idOrKey string
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			idOrKey = v
		case context.Context:
			// Replay currently re-enters the synchronous Canal event path; the
			// context is accepted for API compatibility and future use.
			_ = v
		}
	}

	if idOrKey == "" {
		rec := c.FailedEvent()
		if rec == nil {
			return nil, errors.New("canal: no unresolved failed event")
		}
		return rec, nil
	}

	if rec, ok := j.Get(idOrKey); ok {
		return rec, nil
	}

	// Allow db.table as the selector, choosing its latest unresolved event.
	var latest *RawEventRecord
	for _, rec := range j.Failed() {
		if rec.Key == idOrKey || fmt.Sprintf("%s.%s", rec.Schema, rec.Table) == idOrKey {
			latest = rec
		}
	}
	if latest != nil {
		return latest, nil
	}
	return nil, fmt.Errorf("canal: unknown failed event or table %q", idOrKey)
}
