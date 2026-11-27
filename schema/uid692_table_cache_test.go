package schema_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/stretchr/testify/require"
)

type uid692CountingLoader struct {
	calls    atomic.Int32
	block    chan struct{}
	blockKey string

	mu       sync.Mutex
	versions map[string]any
	tables   map[string]*schema.Table
}

func newUID692CountingLoader() *uid692CountingLoader {
	return &uid692CountingLoader{
		versions: make(map[string]any),
		tables:   make(map[string]*schema.Table),
	}
}

func (l *uid692CountingLoader) LoadTable(_ context.Context, db, table string) (*schema.VersionedTable, error) {
	l.calls.Add(1)
	key := schema.TableKey(db, table)
	if l.block != nil && (l.blockKey == "" || l.blockKey == key) {
		<-l.block
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return &schema.VersionedTable{Table: l.tables[key], Version: l.versions[key]}, nil
}

func uid692Table(columns ...string) *schema.Table {
	t := &schema.Table{Schema: "db", Name: "t"}
	for _, col := range columns {
		t.AddColumn(col, "int", "", "")
	}
	return t
}

func TestUID692VersionCacheHitAndActiveInvalidation(t *testing.T) {
	loader := newUID692CountingLoader()
	loader.tables["db.t"] = uid692Table("id")
	loader.versions["db.t"] = int64(1)
	cache := schema.NewTableCache(loader)

	vt1, err := cache.Get(context.Background(), "db", "t")
	require.NoError(t, err)
	require.Equal(t, int64(1), vt1.Version)
	require.EqualValues(t, 1, loader.calls.Load())

	_, err = cache.Get(context.Background(), "db", "t")
	require.NoError(t, err)
	require.EqualValues(t, 1, loader.calls.Load(), "active version must be a cache hit")

	old, err := cache.GetVersion(context.Background(), "db", "t", int64(1))
	require.NoError(t, err)
	require.Same(t, vt1.Table, old.Table)
	require.EqualValues(t, 1, loader.calls.Load())

	gen := cache.Invalidate("db", "t")
	require.EqualValues(t, 1, gen)
	_, currentOK := cache.Current("db", "t")
	require.False(t, currentOK, "invalidated definition must not be actively returned")

	loader.mu.Lock()
	loader.tables["db.t"] = uid692Table("id", "name")
	loader.versions["db.t"] = int64(2)
	loader.mu.Unlock()

	vt2, err := cache.Get(context.Background(), "db", "t")
	require.NoError(t, err)
	require.Equal(t, int64(2), vt2.Version)
	require.Len(t, vt2.Table.Columns, 2)
	require.EqualValues(t, 2, loader.calls.Load())

	_, err = cache.GetVersion(context.Background(), "db", "t", int64(1))
	require.NoError(t, err)
	require.EqualValues(t, 2, loader.calls.Load(), "old version remains cached and must not fetch")

	cache.Invalidate("db", "t")
	_, err = cache.Get(context.Background(), "db", "t")
	require.NoError(t, err)
	require.EqualValues(t, 3, loader.calls.Load(), "another schema change must actively invalidate")
}

func TestUID692VersionCacheOtherTablesNotBlocked(t *testing.T) {
	loader := newUID692CountingLoader()
	loader.block = make(chan struct{})
	loader.blockKey = "db.a"
	loader.tables["db.a"] = uid692Table("id")
	loader.versions["db.a"] = "a1"
	loader.tables["db.b"] = uid692Table("id")
	loader.versions["db.b"] = "b1"
	cache := schema.NewTableCache(loader)

	aDone := make(chan struct{})
	go func() {
		_, _ = cache.Get(context.Background(), "db", "a")
		close(aDone)
	}()

	require.Eventually(t, func() bool {
		return loader.calls.Load() == 1
	}, time.Second, time.Millisecond)

	bDone := make(chan struct{})
	go func() {
		_, err := cache.Get(context.Background(), "db", "b")
		require.NoError(t, err)
		close(bDone)
	}()

	select {
	case <-bDone:
	case <-time.After(time.Second):
		t.Fatal("rebuilding table a blocked table b")
	}

	close(loader.block)
	select {
	case <-aDone:
	case <-time.After(time.Second):
		t.Fatal("table a rebuild did not finish after release")
	}
}

func TestUID692ResolvePinsDefinitionAcrossInvalidation(t *testing.T) {
	tableV1 := uid692Table("id")
	tableV1.Version = "v1"
	cache := schema.NewTableCache(schema.TableLoaderFunc(func(context.Context, string, string) (*schema.VersionedTable, error) {
		return &schema.VersionedTable{Table: tableV1, Version: "v1"}, nil
	}))
	cache.Put(&schema.VersionedTable{Table: tableV1, Version: "v1"})

	entered := make(chan struct{})
	release := make(chan struct{})
	invalidateDone := make(chan struct{})

	go func() {
		_ = cache.Resolve(context.Background(), "db", "t", func(vt *schema.VersionedTable) error {
			require.Equal(t, "v1", vt.Version)
			close(entered)
			<-release
			return nil
		})
	}()

	<-entered
	go func() {
		cache.Invalidate("db", "t")
		close(invalidateDone)
	}()

	select {
	case <-invalidateDone:
		t.Fatal("invalidation switched definition while event was using it")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-invalidateDone:
	case <-time.After(time.Second):
		t.Fatal("invalidation did not acquire table lock after event completed")
	}
}

func TestUID692SwitchObserverLocatesPoint(t *testing.T) {
	table := uid692Table("id")
	var mu sync.Mutex
	var switches []schema.SwitchRecord
	cache := schema.NewTableCache(nil, schema.WithSwitchObserver(func(rec schema.SwitchRecord) {
		mu.Lock()
		defer mu.Unlock()
		switches = append(switches, rec)
	}))

	cache.Set(table)
	cache.Invalidate("db", "t")
	table2 := uid692Table("id", "extra")
	cache.Set(table2)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, switches, 2)
	require.Equal(t, schema.TableKey("db", "t"), switches[0].Key)
	require.NotEmpty(t, switches[0].ToVersion)
	require.Equal(t, uint64(1), switches[1].Generation)
	require.NotEqual(t, switches[0].ToVersion, switches[1].ToVersion)
}
