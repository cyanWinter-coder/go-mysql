package canal

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
)

// FailedEvent is the domain name for a preserved raw event that could not be
// parsed/applied with the available schema.
type FailedEvent = RawEventRecord

// FailedEventStore is the storage component for failed events.
type FailedEventStore = FailedEventJournal

// NewFailedEventStore creates an in-memory failed-event store.
func NewFailedEventStore() *FailedEventJournal {
	j, _ := NewFailedEventJournal("", slog.Default())
	return j
}

// NewRawEventStore is an alias for NewFailedEventStore.
func NewRawEventStore() *FailedEventJournal { return NewFailedEventStore() }

// TableDispatcher is an alternative name for the per-table event coordinator.
type TableDispatcher = SchemaCoordinator

// SchemaManager is a domain-oriented alias for the per-table schema/event
// coordinator.
type SchemaManager = SchemaCoordinator

// MetadataManager is another domain-oriented alias.
type MetadataManager = SchemaCoordinator

// TableQueue is an alternative name emphasizing per-table queueing.
type TableQueue = SchemaCoordinator

// NewSchemaManager creates a coordinator under a common domain name. Arguments
// are optional and may be a DefinitionSource/schema.TableLoader, a
// RowEventHandler, CoordinatorOption values, a logger, journal, or backoff.
func NewSchemaManager(args ...any) *SchemaCoordinator {
	return newCoordinatorFromArgs(args...)
}

// NewMetadataManager is an alias for NewSchemaManager.
func NewMetadataManager(args ...any) *SchemaCoordinator {
	return NewSchemaManager(args...)
}

// NewTableDispatcher creates a SchemaCoordinator under an alternative name.
func NewTableDispatcher(args ...any) *SchemaCoordinator {
	return newCoordinatorFromArgs(args...)
}

// NewTableQueue creates a SchemaCoordinator under an alternative name.
func NewTableQueue(args ...any) *SchemaCoordinator {
	return newCoordinatorFromArgs(args...)
}

func newCoordinatorFromArgs(args ...any) *SchemaCoordinator {
	var source DefinitionSource
	var handler RowEventHandler
	var opts []CoordinatorOption

	for _, arg := range args {
		switch a := arg.(type) {
		case nil:
			continue
		case DefinitionSource:
			source = a
		case schema.TableLoader:
			source = schema.NewTableCache(a)
		case RowEventHandler:
			handler = a
		case func(context.Context, *replication.BinlogEvent, *schema.Table) error:
			handler = a
		case CoordinatorOption:
			opts = append(opts, a)
		case *slog.Logger:
			opts = append(opts, WithCoordinatorLogger(a))
		case *FailedEventJournal:
			opts = append(opts, WithCoordinatorJournal(a))
		case func(int) time.Duration:
			opts = append(opts, WithRetryBackoff(a))
		default:
			if loader := schema.AsTableLoader(a); loader != nil {
				source = schema.NewTableCache(loader)
			}
		}
	}
	return NewSchemaCoordinator(source, handler, opts...)
}
