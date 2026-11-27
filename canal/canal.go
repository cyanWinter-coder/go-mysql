package canal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/dump"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser"
)

// Canal can sync your MySQL data into everywhere, like Elasticsearch, Redis, etc...
// MySQL must open row format for binlog
type Canal struct {
	m sync.Mutex

	cfg *Config

	parser     *parser.Parser
	master     *masterInfo
	dumper     *dump.Dumper
	dumped     bool
	dumpDoneCh chan struct{}
	syncer     *replication.BinlogSyncer

	eventHandler EventHandler

	connLock sync.Mutex
	conn     *client.Conn

	tableLock          sync.RWMutex
	tables             map[string]*schema.Table
	tableStates        map[string]*tableMetadataState
	errorTablesGetTime map[string]time.Time

	failedEvents  *FailedEventJournal
	failedOnce    sync.Once
	tableExecutor *KeyedExecutor

	tableMatchCache   map[string]bool
	includeTableRegex []*regexp.Regexp
	excludeTableRegex []*regexp.Regexp

	delay atomic.Uint32

	ctx    context.Context
	cancel context.CancelFunc
}

// canal will retry fetching unknown table's meta after UnknownTableRetryPeriod
var (
	UnknownTableRetryPeriod = time.Second * time.Duration(10)
	ErrExcludedTable        = errors.New("excluded table meta")
)

func NewCanal(cfg *Config) (*Canal, error) {
	c := new(Canal)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Dialer == nil {
		dialer := &net.Dialer{}
		cfg.Dialer = dialer.DialContext
	}
	c.cfg = cfg

	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.dumpDoneCh = make(chan struct{})
	c.eventHandler = &DummyEventHandler{}
	c.parser = parser.New()
	c.tables = make(map[string]*schema.Table)
	c.tableStates = make(map[string]*tableMetadataState)
	var err error
	c.failedEvents, err = NewFailedEventJournal(c.cfg.FailedEventStoreDir, c.cfg.Logger)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if c.cfg.DiscardNoMetaRowEvent {
		c.errorTablesGetTime = make(map[string]time.Time)
	}
	c.master = &masterInfo{logger: c.cfg.Logger}

	if err = c.prepareDumper(); err != nil {
		return nil, errors.Trace(err)
	}

	if err = c.prepareSyncer(); err != nil {
		return nil, errors.Trace(err)
	}

	if err := c.checkBinlogRowFormat(); err != nil {
		return nil, errors.Trace(err)
	}

	if err := c.initTableFilter(); err != nil {
		return nil, errors.Trace(err)
	}

	return c, nil
}

func (c *Canal) initTableFilter() error {
	if n := len(c.cfg.IncludeTableRegex); n > 0 {
		c.includeTableRegex = make([]*regexp.Regexp, n)
		for i, val := range c.cfg.IncludeTableRegex {
			reg, err := regexp.Compile(val)
			if err != nil {
				return errors.Trace(err)
			}
			c.includeTableRegex[i] = reg
		}
	}

	if n := len(c.cfg.ExcludeTableRegex); n > 0 {
		c.excludeTableRegex = make([]*regexp.Regexp, n)
		for i, val := range c.cfg.ExcludeTableRegex {
			reg, err := regexp.Compile(val)
			if err != nil {
				return errors.Trace(err)
			}
			c.excludeTableRegex[i] = reg
		}
	}

	if c.includeTableRegex != nil || c.excludeTableRegex != nil {
		c.tableMatchCache = make(map[string]bool)
	}
	return nil
}

func (c *Canal) prepareDumper() error {
	var err error
	dumpPath := c.cfg.Dump.ExecutionPath
	if len(dumpPath) == 0 {
		// ignore mysqldump, use binlog only
		return nil
	}

	if c.dumper, err = dump.NewDumper(dumpPath,
		c.cfg.Addr, c.cfg.User, c.cfg.Password); err != nil {
		return errors.Trace(err)
	}

	if c.dumper == nil {
		// no mysqldump, use binlog only
		return nil
	}

	// use the same logger for the dumper
	c.dumper.Logger = c.cfg.Logger

	dbs := c.cfg.Dump.Databases
	tables := c.cfg.Dump.Tables
	tableDB := c.cfg.Dump.TableDB

	if len(tables) == 0 {
		c.dumper.AddDatabases(dbs...)
	} else {
		c.dumper.AddTables(tableDB, tables...)
	}

	charset := c.cfg.Charset
	c.dumper.SetCharset(charset)

	c.dumper.SetWhere(c.cfg.Dump.Where)
	c.dumper.SkipMasterData(c.cfg.Dump.SkipMasterData)
	c.dumper.SetMaxAllowedPacket(c.cfg.Dump.MaxAllowedPacketMB)
	c.dumper.SetProtocol(c.cfg.Dump.Protocol)
	c.dumper.SetExtraOptions(c.cfg.Dump.ExtraOptions)
	// Use hex blob for mysqldump
	c.dumper.SetHexBlob(true)

	for _, ignoreTable := range c.cfg.Dump.IgnoreTables {
		if seps := strings.Split(ignoreTable, ","); len(seps) == 2 {
			c.dumper.AddIgnoreTables(seps[0], seps[1])
		}
	}

	if c.cfg.Dump.DiscardErr {
		c.dumper.SetErrOut(io.Discard)
	} else {
		c.dumper.SetErrOut(os.Stderr)
	}

	return nil
}

func (c *Canal) GetDelay() uint32 {
	return c.delay.Load()
}

// Run will first try to dump all data from MySQL master `mysqldump`,
// then sync from the binlog position in the dump data.
// It will run forever until meeting an error or Canal closed.
func (c *Canal) Run() error {
	return c.run()
}

// RunFrom will sync from the binlog position directly, ignore mysqldump.
func (c *Canal) RunFrom(pos mysql.Position) error {
	c.master.Update(pos)

	return c.Run()
}

func (c *Canal) StartFromGTID(set mysql.GTIDSet) error {
	c.master.UpdateGTIDSet(set)

	return c.Run()
}

// Dump all data from MySQL master `mysqldump`, ignore sync binlog.
func (c *Canal) Dump() error {
	if c.dumped {
		return errors.New("the method Dump can't be called twice")
	}
	c.dumped = true
	defer close(c.dumpDoneCh)
	return c.dump()
}

func (c *Canal) run() error {
	defer func() {
		c.cancel()
	}()

	c.master.UpdateTimestamp(uint32(utils.Now().Unix()))

	if !c.dumped {
		c.dumped = true

		err := c.tryDump()
		close(c.dumpDoneCh)

		if err != nil {
			c.cfg.Logger.Error("canal dump mysql err", slog.Any("error", err))
			return errors.Trace(err)
		}
	}

	if err := c.runSyncBinlog(); err != nil {
		if errors.Cause(err) != context.Canceled {
			c.cfg.Logger.Error("canal start sync binlog err", slog.Any("error", err))
			return errors.Trace(err)
		}
	}

	return nil
}

func (c *Canal) Close() {
	c.cfg.Logger.Info("closing canal")
	c.m.Lock()
	defer c.m.Unlock()

	c.cancel()
	c.syncer.Close()
	c.connLock.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connLock.Unlock()

	_ = c.eventHandler.OnPosSynced(nil, c.master.Position(), c.master.GTIDSet(), true)
}

func (c *Canal) WaitDumpDone() <-chan struct{} {
	return c.dumpDoneCh
}

func (c *Canal) Ctx() context.Context {
	return c.ctx
}

func (c *Canal) checkTableMatch(key string) bool {
	// no filter, return true
	if c.tableMatchCache == nil {
		return true
	}

	c.tableLock.RLock()
	rst, ok := c.tableMatchCache[key]
	c.tableLock.RUnlock()
	if ok {
		// cache hit
		return rst
	}
	matchFlag := false
	// check include
	if c.includeTableRegex != nil {
		for _, reg := range c.includeTableRegex {
			if reg.MatchString(key) {
				matchFlag = true
				break
			}
		}
	} else {
		matchFlag = true
	}

	// check exclude
	if matchFlag && c.excludeTableRegex != nil {
		for _, reg := range c.excludeTableRegex {
			if reg.MatchString(key) {
				matchFlag = false
				break
			}
		}
	}
	c.tableLock.Lock()
	c.tableMatchCache[key] = matchFlag
	c.tableLock.Unlock()
	return matchFlag
}

// GetTable, ClearTableCache and SetTableCache are implemented in
// table_metadata.go, where per-table rebuild and version state live.

// CheckBinlogRowImage checks MySQL binlog row image, must be in FULL, MINIMAL, NOBLOB
func (c *Canal) CheckBinlogRowImage(image string) error {
	// need to check MySQL binlog row image? full, minimal or noblob?
	// now only log
	if c.cfg.Flavor == mysql.MySQLFlavor {
		res, err := c.Execute(`SHOW GLOBAL VARIABLES LIKE 'binlog_row_image'`)
		if err != nil {
			return errors.Trace(err)
		}
		// MySQL has binlog row image from 5.6, so older will return empty
		rowImage, _ := res.GetString(0, 1)
		if rowImage != "" && !strings.EqualFold(rowImage, image) {
			return errors.Errorf("MySQL uses %s binlog row image, but we want %s", rowImage, image)
		}
	}

	return nil
}

func (c *Canal) checkBinlogRowFormat() error {
	res, err := c.Execute(`SHOW GLOBAL VARIABLES LIKE 'binlog_format';`)
	if err != nil {
		return errors.Trace(err)
	} else if f, _ := res.GetString(0, 1); f != "ROW" {
		return errors.Errorf("binlog must ROW format, but %s now", f)
	}

	return nil
}

func (c *Canal) prepareSyncer() error {
	cfg := replication.BinlogSyncerConfig{
		ServerID:                c.cfg.ServerID,
		Flavor:                  c.cfg.Flavor,
		User:                    c.cfg.User,
		Password:                c.cfg.Password,
		Charset:                 c.cfg.Charset,
		HeartbeatPeriod:         c.cfg.HeartbeatPeriod,
		ReadTimeout:             c.cfg.ReadTimeout,
		UseDecimal:              c.cfg.UseDecimal,
		ParseTime:               c.cfg.ParseTime,
		SemiSyncEnabled:         c.cfg.SemiSyncEnabled,
		MaxReconnectAttempts:    c.cfg.MaxReconnectAttempts,
		DisableRetrySync:        c.cfg.DisableRetrySync,
		TimestampStringLocation: c.cfg.TimestampStringLocation,
		TLSConfig:               c.cfg.TLSConfig,
		Logger:                  c.cfg.Logger,
		Dialer:                  c.cfg.Dialer,
		Localhost:               c.cfg.Localhost,
		EventCacheCount:         c.cfg.EventCacheCount,
		FillZeroLogPos:          c.cfg.FillZeroLogPos,

		RowsEventDecodeFunc: func(event *replication.RowsEvent, data []byte) error {
			pos, err := event.DecodeHeader(data)
			if err != nil {
				return err
			}

			key := fmt.Sprintf("%s.%s", string(event.Table.Schema), string(event.Table.Table))
			if !c.checkTableMatch(key) {
				return nil
			}

			return event.DecodeData(pos, data)
		},
	}

	if strings.Contains(c.cfg.Addr, "/") {
		cfg.Host = c.cfg.Addr
	} else {
		host, port, err := net.SplitHostPort(c.cfg.Addr)
		if err != nil {
			return errors.Errorf("invalid MySQL address format %s, must host:port", c.cfg.Addr)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return errors.Trace(err)
		}

		cfg.Host = host
		cfg.Port = uint16(portNumber)
	}

	c.syncer = replication.NewBinlogSyncer(cfg)

	return nil
}

func (c *Canal) connect(options ...client.Option) (*client.Conn, error) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*10)
	defer cancel()

	return client.ConnectWithDialer(ctx, "", c.cfg.Addr,
		c.cfg.User, c.cfg.Password, "", c.cfg.Dialer, options...)
}

// Execute a SQL
func (c *Canal) Execute(cmd string, args ...any) (rr *mysql.Result, err error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	argF := make([]client.Option, 0)
	if c.cfg.TLSConfig != nil {
		argF = append(argF, func(conn *client.Conn) error {
			conn.SetTLSConfig(c.cfg.TLSConfig)
			return nil
		})
	}

	retryNum := 3
	for range retryNum {
		if c.conn == nil {
			c.conn, err = c.connect(argF...)
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		rr, err = c.conn.Execute(cmd, args...)
		if err != nil {
			if mysql.ErrorEqual(err, mysql.ErrBadConn) {
				c.conn.Close()
				c.conn = nil
				continue
			}
			return nil, err
		}
		break
	}
	return rr, err
}

func (c *Canal) SyncedPosition() mysql.Position {
	return c.master.Position()
}

func (c *Canal) SyncedTimestamp() uint32 {
	return c.master.Timestamp()
}

func (c *Canal) SyncedGTIDSet() mysql.GTIDSet {
	return c.master.GTIDSet()
}
