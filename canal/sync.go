package canal

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser/ast"
)

func (c *Canal) startSyncer() (*replication.BinlogStreamer, error) {
	gset := c.master.GTIDSet()
	if gset == nil || gset.String() == "" {
		pos := c.master.Position()
		s, err := c.syncer.StartSync(pos)
		if err != nil {
			return nil, errors.Errorf("start sync replication at binlog %v error %v", pos, err)
		}
		c.cfg.Logger.Info("start sync binlog at binlog file", slog.Any("pos", pos))
		return s, nil
	}
	gsetClone := gset.Clone()
	s, err := c.syncer.StartSyncGTID(gset)
	if err != nil {
		return nil, errors.Errorf("start sync replication at GTID set %v error %v", gset, err)
	}
	c.cfg.Logger.Info("start sync binlog at GTID set", slog.Any("gset", gsetClone))
	return s, nil
}

func (c *Canal) runSyncBinlog() error {
	s, err := c.startSyncer()
	if err != nil {
		return err
	}

	for {
		ev, err := s.GetEvent(c.ctx)
		if err != nil {
			return errors.Trace(err)
		}

		// Update the delay between the Canal and the Master before the handler hooks are called
		c.updateReplicationDelay(ev)

		switch e := ev.Event.(type) {
		case *replication.RotateEvent:
			// If the timestamp equals zero, the received rotate event is a fake rotate event
			// and contains only the name of the next binlog file. Its log position should be
			// ignored.
			// See https://github.com/mysql/mysql-server/blob/8e797a5d6eb3a87f16498edcb7261a75897babae/sql/rpl_binlog_sender.h#L235
			// and https://github.com/mysql/mysql-server/blob/8cc757da3d87bf4a1f07dcfb2d3c96fed3806870/sql/rpl_binlog_sender.cc#L899
			if ev.Header.Timestamp == 0 {
				fakeRotateLogName := string(e.NextLogName)
				c.cfg.Logger.Info("received fake rotate event", slog.String("nextLogName", string(e.NextLogName)))

				if fakeRotateLogName != c.master.Position().Name {
					c.cfg.Logger.Info("log name changed, the fake rotate event will be handled as a real rotate event")
				} else {
					continue
				}
			}
		}

		err = c.handleEvent(ev)
		if err != nil {
			return err
		}
	}
}

func (c *Canal) handleEvent(ev *replication.BinlogEvent) error {
	savePos := false
	force := false
	pos := c.master.Position()
	var err error

	curPos := pos.Pos

	// next binlog pos
	pos.Pos = ev.Header.LogPos

	// We only save position with RotateEvent and XIDEvent.
	// For RowsEvent, we can't save the position until meeting XIDEvent
	// which tells the whole transaction is over.
	// TODO: If we meet any DDL query, we must save too.
	switch e := ev.Event.(type) {
	case *replication.RotateEvent:
		pos.Name = string(e.NextLogName)
		pos.Pos = uint32(e.Position)
		c.cfg.Logger.Info("rotate binlog", slog.Any("pos", pos))
		savePos = true
		force = true
		if err = c.eventHandler.OnRotate(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.RowsEvent:
		// we only focus row based event
		if err := c.handleRowsEvent(ev); err != nil {
			c.cfg.Logger.Error("handle rows event", slog.String("file", pos.Name), slog.Uint64("position", uint64(curPos)), slog.Any("error", err))
			return errors.Trace(err)
		}
		return nil
	case *replication.TransactionPayloadEvent:
		// handle subevent row by row
		ev := ev.Event.(*replication.TransactionPayloadEvent)
		for _, subEvent := range ev.Events {
			err = c.handleEvent(subEvent)
			if err != nil {
				c.cfg.Logger.Error("handle transaction payload subevent", slog.String("file", pos.Name), slog.Uint64("position", uint64(curPos)), slog.Any("error", err))
				return errors.Trace(err)
			}
		}
		return nil
	case *replication.XIDEvent:
		savePos = true
		// try to save the position later
		if err := c.eventHandler.OnXID(ev.Header, pos); err != nil {
			return errors.Trace(err)
		}
		if e.GSet != nil {
			c.master.UpdateGTIDSet(e.GSet)
		}
	case *replication.MariadbGTIDEvent:
		if err := c.eventHandler.OnGTID(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.GTIDEvent:
		if err := c.eventHandler.OnGTID(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.GtidTaggedLogEvent:
		if err := c.eventHandler.OnGTID(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.RowsQueryEvent:
		if err := c.eventHandler.OnRowsQueryEvent(e); err != nil {
			return errors.Trace(err)
		}
	case *replication.MariadbAnnotateRowsEvent:
		if err := c.eventHandler.OnRowsQueryEvent(&replication.RowsQueryEvent{Query: e.Query}); err != nil {
			return errors.Trace(err)
		}
	case *replication.QueryEvent:
		stmts, _, err := c.parser.Parse(string(e.Query), "", "")
		queryParseErr := err
		if queryParseErr != nil {
			c.preserveUnparsedQueryEvent(ev, string(e.Query), queryParseErr)
			if h, ok := c.eventHandler.(UnparsedQueryHandler); ok {
				handlerErr := h.OnUnparsedQuery(ev.Header, pos, e, queryParseErr)
				if handlerErr != nil {
					c.markLatestRawEventFailed(handlerErr)
					return errors.Trace(handlerErr)
				}
				c.markLatestRawEventResolved()
				return nil
			}
			// The parser does not understand all syntax.
			// For example, it won't parse [CREATE|DROP] TRIGGER statements.
			c.baseLogger().Error("error parsing query, will skip this event but raw event is preserved", slog.String("query", string(e.Query)), slog.Any("error", queryParseErr))
			return nil
		}
		for _, stmt := range stmts {
			switch stmt.(type) {
			case *ast.BeginStmt, *ast.SavepointStmt:
				// transaction not yet complete; checkpointing here would skip it on GTID resume
				continue
			}
			savePos = true
			nodes := parseStmt(stmt)
			for _, node := range nodes {
				if node.db == "" {
					node.db = string(e.Schema)
				}
				if err = c.updateTable(ev.Header, node.db, node.table); err != nil {
					return errors.Trace(err)
				}
			}
			if len(nodes) > 0 {
				force = true
				// Now we only handle Table Changed DDL, maybe we will support more later.
				if err = c.eventHandler.OnDDL(ev.Header, pos, e); err != nil {
					return errors.Trace(err)
				}
			}
		}
		if savePos && e.GSet != nil {
			c.master.UpdateGTIDSet(e.GSet)
		}
	default:
		return nil
	}

	if savePos {
		c.master.Update(pos)
		c.master.UpdateTimestamp(ev.Header.Timestamp)

		if err := c.eventHandler.OnPosSynced(ev.Header, pos, c.master.GTIDSet(), force); err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

type node struct {
	db    string
	table string
}

func parseStmt(stmt ast.StmtNode) (ns []*node) {
	switch t := stmt.(type) {
	case *ast.RenameTableStmt:
		ns = make([]*node, len(t.TableToTables))
		for i, tableInfo := range t.TableToTables {
			ns[i] = &node{
				db:    tableInfo.OldTable.Schema.String(),
				table: tableInfo.OldTable.Name.String(),
			}
		}
	case *ast.AlterTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.DropTableStmt:
		ns = make([]*node, len(t.Tables))
		for i, table := range t.Tables {
			ns[i] = &node{
				db:    table.Schema.String(),
				table: table.Name.String(),
			}
		}
	case *ast.CreateTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.TruncateTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.CreateIndexStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.DropIndexStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	}
	return ns
}

func (c *Canal) updateTable(header *replication.EventHeader, db, table string) (err error) {
	c.ClearTableCache([]byte(db), []byte(table))
	c.baseLogger().Info("table structure changed, clear table cache", slog.String("database", db), slog.String("table", table))
	if err = c.eventHandler.OnTableChanged(header, db, table); err != nil && errors.Cause(err) != schema.ErrTableNotExist {
		return errors.Trace(err)
	}
	return err
}

func (c *Canal) updateReplicationDelay(ev *replication.BinlogEvent) {
	var newDelay uint32
	now := uint32(utils.Now().Unix())
	if now >= ev.Header.Timestamp {
		newDelay = now - ev.Header.Timestamp
	}
	c.delay.Store(newDelay)
}

func (c *Canal) handleRowsEvent(e *replication.BinlogEvent) error {
	ev := e.Event.(*replication.RowsEvent)

	// Caveat: table may be altered at runtime.
	schemaName := string(ev.Table.Schema)
	tableName := string(ev.Table.Table)

	action, err := rowActionForType(e.Header.EventType)
	if err != nil {
		return err
	}

	// Serialize events for this table around metadata lookup and OnRow. DDL
	// invalidation cannot let a second event for the same table enter with a
	// new definition while this callback is still using the old one. Other
	// tables have independent keys and continue concurrently.
	key := schema.TableKey(schemaName, tableName)
	err = c.tableEventExecutor().Do(key, func() error {
		t, getErr := c.GetTable(schemaName, tableName)
		if getErr != nil {
			return getErr
		}
		events := newRowsEvent(t, action, ev.Rows, e.Header, ev)
		return c.eventHandler.OnRow(events)
	})
	if err != nil {
		cause := errors.Cause(err)
		// ignore errors below
		if cause == ErrExcludedTable || cause == schema.ErrMissingTableMeta {
			return nil
		}
		// Allow handler to decide what to do when table is missing.
		if cause == schema.ErrTableNotExist {
			return c.eventHandler.OnTableNotFound(e.Header, ev)
		}
		c.preserveFailedEvent(e, schemaName, tableName, err)
		return err
	}
	return nil
}

func rowActionForType(eventType replication.EventType) (string, error) {
	switch eventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2, replication.MARIADB_WRITE_ROWS_COMPRESSED_EVENT_V1:
		return InsertAction, nil
	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2, replication.MARIADB_DELETE_ROWS_COMPRESSED_EVENT_V1:
		return DeleteAction, nil
	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2, replication.MARIADB_UPDATE_ROWS_COMPRESSED_EVENT_V1:
		return UpdateAction, nil
	default:
		return "", errors.Errorf("%s not supported now", eventType)
	}
}

// preserveFailedEvent keeps the untouched binlog event when schema resolution
// or row handling fails. Preservation never replaces the original error.
func (c *Canal) preserveFailedEvent(e *replication.BinlogEvent, schemaName, tableName string, cause error) {
	journal := c.RawEventJournal()
	if journal == nil || e == nil {
		return
	}

	position := c.safeMasterPosition()
	rec := &RawEventRecord{
		Schema:    schemaName,
		Table:     tableName,
		Key:       schema.TableKey(schemaName, tableName),
		Position:  position.Name,
		LogPos:    e.Header.LogPos,
		EventType: e.Header.EventType.String(),
		Raw:       e.RawData,
		Binlog:    e,
		LastError: cause.Error(),
	}
	if position.Name != "" {
		rec.Position = position.String()
	}
	if _, err := journal.Save(rec); err != nil {
		c.baseLogger().Error("preserve raw failed row event", slog.Any("error", err))
	}
}

func (c *Canal) preserveUnparsedQueryEvent(e *replication.BinlogEvent, query string, cause error) *RawEventRecord {
	journal := c.RawEventJournal()
	if journal == nil || e == nil {
		return nil
	}

	position := c.safeMasterPosition()
	rec := &RawEventRecord{
		Kind:      "unparsed-ddl",
		Query:     query,
		Position:  position.String(),
		Raw:       e.RawData,
		Binlog:    e,
		LastError: cause.Error(),
	}
	if e.Header != nil {
		rec.LogPos = e.Header.LogPos
		rec.EventType = e.Header.EventType.String()
	}
	saved, err := journal.Save(rec)
	if err != nil {
		c.baseLogger().Error("preserve raw unparsed query event", slog.Any("error", err))
		return rec
	}
	return saved
}

func (c *Canal) markLatestRawEventResolved() {
	journal := c.RawEventJournal()
	records := journal.List()
	if len(records) == 0 {
		return
	}
	if err := journal.Resolve(records[len(records)-1].ID); err != nil {
		c.baseLogger().Error("resolve preserved query event", slog.Any("error", err))
	}
}

func (c *Canal) markLatestRawEventFailed(cause error) {
	journal := c.RawEventJournal()
	records := journal.List()
	if len(records) == 0 {
		return
	}
	rec := records[len(records)-1]
	rec.Resolved = false
	rec.LastError = cause.Error()
	if _, err := journal.Save(rec); err != nil {
		c.baseLogger().Error("update preserved query event", slog.Any("error", err))
	}
}

func (c *Canal) FlushBinlog() error {
	_, err := c.Execute("FLUSH BINARY LOGS")
	return errors.Trace(err)
}

func (c *Canal) WaitUntilPos(pos mysql.Position, timeout time.Duration) error {
	return c.WaitUntilPosContext(context.Background(), pos, timeout)
}

func (c *Canal) WaitUntilPosContext(ctx context.Context, pos mysql.Position, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.Errorf("wait position %v too long > %s", pos, timeout)
		default:
			if !c.cfg.DisableFlushBinlogWhileWaiting {
				err := c.FlushBinlog()
				if err != nil {
					return errors.Trace(err)
				}
			}
			curPos := c.master.Position()
			if curPos.Compare(pos) >= 0 {
				return nil
			} else {
				c.cfg.Logger.Debug("master pos is behind, wait to catch up", slog.String("master file", curPos.Name), slog.Uint64("master position", uint64(curPos.Pos)),
					slog.String("target file", pos.Name), slog.Uint64("target position", uint64(curPos.Pos)))
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// getShowBinaryLogQuery returns the correct SQL statement to query binlog status
// for the given database flavor and server version.
//
// Sources:
//
//	MySQL:   https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-0.html
//	MariaDB: https://mariadb.com/kb/en/show-binlog-status
func getShowBinaryLogQuery(flavor, serverVersion string) string {
	switch flavor {
	case mysql.MariaDBFlavor:
		eq, err := mysql.CompareServerVersions(serverVersion, "10.5.2")
		if (err == nil) && (eq >= 0) {
			return "SHOW BINLOG STATUS"
		}
	case mysql.MySQLFlavor:
		eq, err := mysql.CompareServerVersions(serverVersion, "8.4.0")
		if (err == nil) && (eq >= 0) {
			return "SHOW BINARY LOG STATUS"
		}
	}

	return "SHOW MASTER STATUS"
}

func (c *Canal) GetMasterPos() (mysql.Position, error) {
	query := getShowBinaryLogQuery(c.cfg.Flavor, c.conn.GetServerVersion())

	rr, err := c.Execute(query)
	if err != nil {
		return mysql.Position{}, errors.Trace(err)
	}

	name, _ := rr.GetString(0, 0)
	pos, _ := rr.GetInt(0, 1)

	return mysql.Position{Name: name, Pos: uint32(pos)}, nil
}

func (c *Canal) GetMasterGTIDSet() (mysql.GTIDSet, error) {
	query := ""
	switch c.cfg.Flavor {
	case mysql.MariaDBFlavor:
		query = "SELECT @@GLOBAL.gtid_current_pos"
	default:
		query = "SELECT @@GLOBAL.GTID_EXECUTED"
	}
	rr, err := c.Execute(query)
	if err != nil {
		return nil, errors.Trace(err)
	}
	gx, err := rr.GetString(0, 0)
	if err != nil {
		return nil, errors.Trace(err)
	}
	gset, err := mysql.ParseGTIDSet(c.cfg.Flavor, gx)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return gset, nil
}

func (c *Canal) CatchMasterPos(timeout time.Duration) error {
	return c.CatchMasterPosContext(context.Background(), timeout)
}

func (c *Canal) CatchMasterPosContext(ctx context.Context, timeout time.Duration) error {
	pos, err := c.GetMasterPos()
	if err != nil {
		return errors.Trace(err)
	}

	return c.WaitUntilPosContext(ctx, pos, timeout)
}
