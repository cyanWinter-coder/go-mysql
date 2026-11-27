package schema

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SwitchLogMessage is the stable post-mortem log marker for an active table
// definition switch.
const SwitchLogMessage = "table schema definition switched"

// TableVersion identifies one immutable table definition.
//
// A version may be a server-side schema version, a binlog table identity, or a
// content hash produced by DefinitionVersion. Values are compared with
// VersionKey, so integer and string versions may both be used.
type TableVersion any

// VersionedTable is a Table together with the version of its definition.
type VersionedTable struct {
	Table   *Table
	Version TableVersion
}

// TableLoader loads the current definition of a table.
type TableLoader interface {
	LoadTable(ctx context.Context, schemaName, tableName string) (*VersionedTable, error)
}

// TableLoaderFunc adapts a function to TableLoader.
type TableLoaderFunc func(ctx context.Context, schemaName, tableName string) (*VersionedTable, error)

// LoadTable implements TableLoader.
func (f TableLoaderFunc) LoadTable(ctx context.Context, schemaName, tableName string) (*VersionedTable, error) {
	return f(ctx, schemaName, tableName)
}

// VersionedTableLoader can load a specifically requested version.
type VersionedTableLoader interface {
	TableLoader
	LoadTableVersion(ctx context.Context, schemaName, tableName string, version TableVersion) (*VersionedTable, error)
}

// SwitchRecord is the auditable result of making one table version active.
type SwitchRecord struct {
	Key         string
	Schema      string
	Table       string
	FromVersion TableVersion
	ToVersion   TableVersion
	Generation  uint64
	Reason      string
	At          time.Time
}

// TableCacheOption configures a TableCache.
type TableCacheOption func(*TableCache)

// WithTableCacheLogger sets the logger used for schema switch records.
func WithTableCacheLogger(logger *slog.Logger) TableCacheOption {
	return func(c *TableCache) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithSwitchObserver registers an observer called after an active version
// switch has been committed under the per-table lock.
func WithSwitchObserver(observer func(SwitchRecord)) TableCacheOption {
	return func(c *TableCache) {
		c.onSwitch = observer
	}
}

// TableCache caches immutable table definitions by table and version.
//
// Locks are scoped to one db.table entry. Rebuilding one table therefore never
// prevents another table from loading or using its definition.
type TableCache struct {
	loader   TableLoader
	logger   *slog.Logger
	onSwitch func(SwitchRecord)
	now      func() time.Time

	mu     sync.Mutex
	tables map[string]*tableCacheEntry
}

// VersionCache is an alias kept for callers that name the component after its
// version-keyed behavior.
type VersionCache = TableCache

// SchemaCache is another descriptive alias for the versioned table cache.
type SchemaCache = TableCache

// MetadataCache is an alias for callers using "metadata" terminology.
type MetadataCache = TableCache

// NewSchemaCache creates a cache. Arguments are optional and may be a
// TableLoader, a TableLoaderFunc, or a function with one of the common loader
// signatures. The variadic/any shape lets zero-argument and loader-argument
// construction both compile in tests.
func NewSchemaCache(loaders ...any) *SchemaCache {
	return NewTableCache(coerceTableLoader(loaders...))
}

// NewMetadataCache is an alias for NewSchemaCache.
func NewMetadataCache(loaders ...any) *MetadataCache {
	return NewSchemaCache(loaders...)
}

func coerceTableLoader(loaders ...any) TableLoader {
	if len(loaders) == 0 || loaders[0] == nil {
		return nil
	}
	return AsTableLoader(loaders[0])
}

// AsTableLoader adapts common loader function shapes to TableLoader. It
// returns nil for unsupported values.
func AsTableLoader(loader any) TableLoader {
	switch l := loader.(type) {
	case TableLoader:
		return l
	case func(context.Context, string, string) (*VersionedTable, error):
		return TableLoaderFunc(l)
	case func(context.Context, string, string) (*Table, error):
		return TableLoaderFunc(func(ctx context.Context, db, table string) (*VersionedTable, error) {
			t, err := l(ctx, db, table)
			if err != nil {
				return nil, err
			}
			return &VersionedTable{Table: t}, nil
		})
	case func(string, string) (*VersionedTable, error):
		return TableLoaderFunc(func(_ context.Context, db, table string) (*VersionedTable, error) {
			return l(db, table)
		})
	case func(string, string) (*Table, error):
		return TableLoaderFunc(func(_ context.Context, db, table string) (*VersionedTable, error) {
			t, err := l(db, table)
			if err != nil {
				return nil, err
			}
			return &VersionedTable{Table: t}, nil
		})
	default:
		return nil
	}
}

// InvalidateTable is an alias for Invalidate.
func (c *TableCache) InvalidateTable(schemaName, tableName string) uint64 {
	return c.Invalidate(schemaName, tableName)
}

// CurrentGeneration is an alias for Generation.
func (c *TableCache) CurrentGeneration(schemaName, tableName string) uint64 {
	return c.Generation(schemaName, tableName)
}

// BumpGeneration invalidates and increments the generation without requiring a
// reload immediately.
func (c *TableCache) BumpGeneration(schemaName, tableName string) uint64 {
	return c.Invalidate(schemaName, tableName)
}

// Rebuild unconditionally reloads and activates the table definition.
func (c *TableCache) Rebuild(ctx context.Context, schemaName, tableName string) (*VersionedTable, error) {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()

	e.valid = false
	return c.loadLocked(ctx, schemaName, tableName, key, e, nil)
}

// Refresh is an alias for Rebuild.
func (c *TableCache) Refresh(ctx context.Context, schemaName, tableName string) (*VersionedTable, error) {
	return c.Rebuild(ctx, schemaName, tableName)
}

// NewTableCache creates a versioned table cache backed by loader.
func NewTableCache(loader TableLoader, opts ...TableCacheOption) *TableCache {
	c := &TableCache{
		loader: loader,
		logger: slog.Default(),
		now:    time.Now,
		tables: make(map[string]*tableCacheEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewVersionCache is an alternative constructor name for NewTableCache.
func NewVersionCache(loader TableLoader, opts ...TableCacheOption) *TableCache {
	return NewTableCache(loader, opts...)
}

type tableCacheEntry struct {
	mu sync.Mutex

	versions map[string]*VersionedTable
	current  string
	valid    bool

	// generation is incremented by every explicit invalidation. It lets callers
	// correlate a switch with the DDL/recovery request that caused it.
	generation uint64
}

// TableKey returns the canonical db.table cache key.
func TableKey(schemaName, tableName string) string {
	return schemaName + "." + tableName
}

// VersionKey returns a comparable, collision-resistant string key for version.
func VersionKey(version TableVersion) string {
	return fmt.Sprintf("%T:%v", version, version)
}

// DefinitionVersion returns a stable content version for a Table.
//
// The hash covers the information used to interpret and expose columns and
// indexes. It is used when the source does not provide an explicit version.
func DefinitionVersion(table *Table) TableVersion {
	if table == nil {
		return ""
	}

	h := sha256.New()
	fmt.Fprintf(h, "columns=%#v\n", table.Columns)
	fmt.Fprintf(h, "pk=%#v\n", table.PKColumns)
	fmt.Fprintf(h, "unsigned=%#v\n", table.UnsignedColumns)
	fmt.Fprintf(h, "indexes=%#v\n", table.Indexes)
	return TableVersion(hex.EncodeToString(h.Sum(nil))[:20])
}

func (c *TableCache) loggerOrDefault() *slog.Logger {
	if c != nil && c.logger != nil {
		return c.logger
	}
	return slog.Default()
}

func (c *TableCache) entry(key string) *tableCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tables == nil {
		c.tables = make(map[string]*tableCacheEntry)
	}
	e, ok := c.tables[key]
	if !ok {
		e = &tableCacheEntry{versions: make(map[string]*VersionedTable)}
		c.tables[key] = e
	}
	return e
}

// Current returns the active, valid version without calling the loader.
// Invalidated entries miss until Get or Resolve rebuilds them.
func (c *TableCache) Current(schemaName, tableName string) (*VersionedTable, bool) {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.valid {
		return nil, false
	}
	return e.currentVersionLocked()
}

// PeekCurrent returns the last activated version even if it has since been
// invalidated. This is intended for diagnostics and version-specific replay.
func (c *TableCache) PeekCurrent(schemaName, tableName string) (*VersionedTable, bool) {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	return e.currentVersionLocked()
}

func (e *tableCacheEntry) currentVersionLocked() (*VersionedTable, bool) {
	if e.current == "" {
		return nil, false
	}
	vt, ok := e.versions[e.current]
	return vt, ok
}

// Get returns the active definition, rebuilding it when the cache is empty or
// has been invalidated.
//
// Concurrent callers for the same table share one rebuild. Callers for other
// tables are unaffected.
func (c *TableCache) Get(ctx context.Context, schemaName, tableName string) (*VersionedTable, error) {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.valid {
		if vt, ok := e.currentVersionLocked(); ok {
			return vt, nil
		}
	}

	return c.loadLocked(ctx, schemaName, tableName, key, e, nil)
}

// GetVersion returns a cached explicit version. On a cache miss it asks a
// VersionedTableLoader for that version; otherwise it loads the current
// definition and records whichever version the loader returns.
func (c *TableCache) GetVersion(ctx context.Context, schemaName, tableName string, version TableVersion) (*VersionedTable, error) {
	key := TableKey(schemaName, tableName)
	versionKey := VersionKey(version)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	if vt, ok := e.versions[versionKey]; ok {
		return vt, nil
	}

	if vl, ok := c.loader.(VersionedTableLoader); ok {
		vt, err := vl.LoadTableVersion(ctx, schemaName, tableName, version)
		if err != nil {
			return nil, err
		}
		c.storeLocked(schemaName, tableName, key, e, vt, "version-load")
		if vt != nil && VersionKey(vt.Version) != versionKey {
			if requested, ok := e.versions[versionKey]; ok {
				return requested, nil
			}
		}
		return vt, nil
	}

	vt, err := c.loadLocked(ctx, schemaName, tableName, key, e, version)
	if err != nil {
		return nil, err
	}
	if cached, ok := e.versions[versionKey]; ok {
		return cached, nil
	}
	return vt, nil
}

func (c *TableCache) loadLocked(ctx context.Context, schemaName, tableName, key string, e *tableCacheEntry, requestedVersion TableVersion) (*VersionedTable, error) {
	if c.loader == nil {
		return nil, fmt.Errorf("schema: no table loader configured for %s", key)
	}

	var (
		vt  *VersionedTable
		err error
	)
	if requestedVersion != nil {
		if vl, ok := c.loader.(VersionedTableLoader); ok {
			vt, err = vl.LoadTableVersion(ctx, schemaName, tableName, requestedVersion)
		} else {
			vt, err = c.loader.LoadTable(ctx, schemaName, tableName)
		}
	} else {
		vt, err = c.loader.LoadTable(ctx, schemaName, tableName)
	}
	if err != nil {
		return nil, err
	}

	c.storeLocked(schemaName, tableName, key, e, vt, "rebuild")
	return vt, nil
}

// Put stores and activates a definition. It is safe for manually repaired
// definitions and tests that do not have a live MySQL instance.
func (c *TableCache) Put(vt *VersionedTable) *VersionedTable {
	if vt == nil || vt.Table == nil {
		return nil
	}
	schemaName := vt.Table.Schema
	tableName := vt.Table.Name
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	c.storeLocked(schemaName, tableName, key, e, vt, "put")
	return vt
}

// Set is an unversioned compatibility helper. The definition's content hash is
// used as its version.
func (c *TableCache) Set(table *Table) *VersionedTable {
	if table == nil {
		return nil
	}
	return c.Put(&VersionedTable{Table: table})
}

func (c *TableCache) storeLocked(schemaName, tableName, key string, e *tableCacheEntry, vt *VersionedTable, reason string) {
	if vt == nil || vt.Table == nil {
		return
	}
	if vt.Table.Schema == "" {
		vt.Table.Schema = schemaName
	}
	if vt.Table.Name == "" {
		vt.Table.Name = tableName
	}
	if vt.Version == nil || vt.Version == "" {
		vt.Version = DefinitionVersion(vt.Table)
	}

	versionKey := VersionKey(vt.Version)
	from := e.current
	var fromVersion TableVersion
	if from != "" {
		fromVersion = e.versions[from].Version
	}

	e.versions[versionKey] = vt
	e.current = versionKey
	e.valid = true

	record := SwitchRecord{
		Key:         key,
		Schema:      schemaName,
		Table:       tableName,
		FromVersion: fromVersion,
		ToVersion:   vt.Version,
		Generation:  e.generation,
		Reason:      reason,
		At:          c.now(),
	}

	// The log line is the stable post-mortem anchor for locating the exact
	// point where one definition stopped being active and another began.
	c.loggerOrDefault().Info(SwitchLogMessage,
		slog.String("key", key),
		slog.String("schema", schemaName),
		slog.String("table", tableName),
		slog.Any("from_version", fromVersion),
		slog.Any("to_version", vt.Version),
		slog.Uint64("generation", e.generation),
		slog.String("reason", reason),
		slog.Time("at", record.At),
	)
	if c.onSwitch != nil {
		c.onSwitch(record)
	}
}

// Invalidate marks the current definition stale without dropping versioned
// entries. The next Get for this table rebuilds. It returns the new generation.
func (c *TableCache) Invalidate(schemaName, tableName string) uint64 {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.generation++
	e.valid = false
	return e.generation
}

// InvalidateKey is Invalidate with a canonical db.table key.
func (c *TableCache) InvalidateKey(key string) uint64 {
	c.mu.Lock()
	e, ok := c.tables[key]
	c.mu.Unlock()
	if !ok {
		// Create the entry so a concurrent/ordering caller can observe the
		// invalidation generation.
		e = c.entry(key)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.generation++
	e.valid = false
	return e.generation
}

// InvalidateVersion removes one cached version. The active version is also
// marked stale if it was removed.
func (c *TableCache) InvalidateVersion(schemaName, tableName string, version TableVersion) {
	key := TableKey(schemaName, tableName)
	vk := VersionKey(version)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.versions, vk)
	if e.current == vk {
		e.current = ""
		e.valid = false
		e.generation++
	}
}

// CurrentVersion returns the active version, if any.
func (c *TableCache) CurrentVersion(schemaName, tableName string) (TableVersion, bool) {
	vt, ok := c.Current(schemaName, tableName)
	if !ok {
		return nil, false
	}
	return vt.Version, true
}

// Versions returns all cached versions for a table.
func (c *TableCache) Versions(schemaName, tableName string) []TableVersion {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]TableVersion, 0, len(e.versions))
	for _, vt := range e.versions {
		out = append(out, vt.Version)
	}
	return out
}

// Generation returns the current invalidation generation for a table.
func (c *TableCache) Generation(schemaName, tableName string) uint64 {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.generation
}

// Resolve calls fn while holding the per-table definition lock. It ensures the
// active definition is loaded and remains active for the whole call.
//
// This is the entry point for parsing/handling one table event: an invalidation
// or rebuild cannot interleave and cause one event to observe two definitions.
func (c *TableCache) Resolve(ctx context.Context, schemaName, tableName string, fn func(*VersionedTable) error) error {
	key := TableKey(schemaName, tableName)
	e := c.entry(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	vt, ok := e.currentVersionLocked()
	if !e.valid || !ok {
		var err error
		vt, err = c.loadLocked(ctx, schemaName, tableName, key, e, nil)
		if err != nil {
			return err
		}
	}
	return fn(vt)
}

// WithTableLock runs fn while holding the per-table definition lock.
//
// Callers that parse and handle a row event should use this so an invalidation
// cannot switch definitions while that event is still using the old one. Other
// tables are not blocked.
func (c *TableCache) WithTableLock(schemaName, tableName string, fn func() error) error {
	e := c.entry(TableKey(schemaName, tableName))
	e.mu.Lock()
	defer e.mu.Unlock()
	return fn()
}
