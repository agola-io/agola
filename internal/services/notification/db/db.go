package db

import (
	"context"
	stdsql "database/sql"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/notification/db/objects"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/notification/types"
)

//go:generate ../../../../tools/bin/dbgenerator -type db -component notification

type DB struct {
	log zerolog.Logger
	sdb *sql.DB
}

func NewDB(log zerolog.Logger, sdb *sql.DB) (*DB, error) {
	return &DB{
		log: log,
		sdb: sdb,
	}, nil
}

func (d *DB) DBType() sql.Type {
	return d.sdb.Type()
}

func (d *DB) DB() *sql.DB {
	return d.sdb
}

func (d *DB) Do(ctx context.Context, f func(tx *sql.Tx) error) error {
	return errors.WithStack(d.sdb.Do(ctx, f))
}

func (d *DB) ObjectsInfo() []sqlg.ObjectInfo {
	return objects.ObjectsInfo
}

func (d *DB) Flavor() sq.Flavor {
	switch d.sdb.Type() {
	case sql.Postgres:
		return sq.PostgreSQL
	case sql.Sqlite3:
		return sq.SQLite
	}

	return sq.PostgreSQL
}

func (d *DB) exec(tx *sql.Tx, rq sq.Builder) (stdsql.Result, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) query(tx *sql.Tx, rq sq.Builder) (*stdsql.Rows, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("start q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Query(q, args...)
	// d.log.Debug().Msgf("end q: %s, args: %s", q, util.Dump(args))
	return r, errors.WithStack(err)
}

func mustSingleRow[T any](s []*T) (*T, error) {
	if len(s) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(s) == 0 {
		return nil, nil
	}

	return s[0], nil
}

func (d *DB) GetRunWebhookDeliveriesAfterSequence(tx *sql.Tx, afterSequence uint64, limit int) ([]*types.RunWebhookDelivery, error) {
	q := runWebhookDeliverySelect().OrderBy("sequence").Asc()
	q.Where(q.G("sequence", afterSequence))
	if limit > 0 {
		q.Limit(limit)
	}

	runWebhookDeliveries, _, err := d.fetchRunWebhookDeliverys(tx, q)
	return runWebhookDeliveries, errors.WithStack(err)
}

func (d *DB) GetProjectRunWebhookDeliveriesAfterSequenceByProjectID(tx *sql.Tx, afterSequence uint64, projectID string, deliveryStatusFilter []types.DeliveryStatus, limit int, sortDirection types.SortDirection) ([]*types.RunWebhookDelivery, error) {
	q := runWebhookDeliverySelect().OrderBy("sequence")

	if projectID != "" {
		q.Join("runwebhook", "runwebhook.id = runwebhookdelivery.run_webhook_id")
		q.Where(q.E("runwebhook.project_id", projectID))
	}
	if len(deliveryStatusFilter) > 0 {
		q.Where(q.In("delivery_status", sq.Flatten(deliveryStatusFilter)...))
	}

	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}
	if afterSequence > 0 {
		switch sortDirection {
		case types.SortDirectionAsc:
			q.Where(q.G("sequence", afterSequence))
		case types.SortDirectionDesc:
			q.Where(q.L("sequence", afterSequence))
		}
	}

	if limit > 0 {
		q.Limit(limit)
	}

	runWebhookDeliveries, _, err := d.fetchRunWebhookDeliverys(tx, q)
	return runWebhookDeliveries, errors.WithStack(err)
}

func (d *DB) GetRunWebhookDeliveriesByRunWebhookID(tx *sql.Tx, runWebhookID string, deliveryStatusFilter []types.DeliveryStatus, limit int, sortDirection types.SortDirection) ([]*types.RunWebhookDelivery, error) {
	q := runWebhookDeliverySelect().OrderBy("sequence")
	q.Where(q.E("run_webhook_id", runWebhookID))

	if len(deliveryStatusFilter) > 0 {
		q.Where(q.In("delivery_status", sq.Flatten(deliveryStatusFilter)...))
	}

	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}

	if limit > 0 {
		q.Limit(limit)
	}

	runWebhookDeliveries, _, err := d.fetchRunWebhookDeliverys(tx, q)
	return runWebhookDeliveries, errors.WithStack(err)
}

func (d *DB) GetRunWebhookDeliveryByID(tx *sql.Tx, runWebhookDeliveryID string) (*types.RunWebhookDelivery, error) {
	q := runWebhookDeliverySelect()
	q.Where(q.E("id", runWebhookDeliveryID))
	runWebhookDeliveries, _, err := d.fetchRunWebhookDeliverys(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runWebhookDeliveries)
	return out, errors.WithStack(err)
}

func (d *DB) DeleteRunWebhookDeliveriesByRunWebhookID(tx *sql.Tx, runWebhookID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("runwebhookdelivery")
	q.Where(q.E("run_webhook_id", runWebhookID))

	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete runWebhookdeliveries")
	}

	return nil
}

func (d *DB) GetRunWebhookByID(tx *sql.Tx, runWebhookID string) (*types.RunWebhook, error) {
	q := runWebhookSelect()
	q.Where(q.E("id", runWebhookID))
	runWebhooks, _, err := d.fetchRunWebhooks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runWebhooks)
	return out, errors.WithStack(err)
}

func (d *DB) GetRunWebhooks(tx *sql.Tx, limit int) ([]*types.RunWebhook, error) {
	q := runWebhookSelect()
	if limit > 0 {
		q.Limit(limit)
	}
	runWebhooks, _, err := d.fetchRunWebhooks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return runWebhooks, errors.WithStack(err)
}

func (d *DB) GetRunWebhooksAfterRunWebhookID(tx *sql.Tx, afterRunWebhookID string, limit int) ([]*types.RunWebhook, error) {
	q := runWebhookSelect().OrderBy("id")
	if afterRunWebhookID != "" {
		q.Where(q.G("id", afterRunWebhookID))
	}

	if limit > 0 {
		q.Limit(limit)
	}
	runWebhooks, _, err := d.fetchRunWebhooks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return runWebhooks, errors.WithStack(err)
}

func (d *DB) GetLastRunEventSequence(tx *sql.Tx) (*types.LastRunEventSequence, error) {
	q := lastRunEventSequenceSelect()
	lastRunEventSequences, _, err := d.fetchLastRunEventSequences(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(lastRunEventSequences)
	return out, errors.WithStack(err)
}

func (d *DB) GetCommitStatusDeliveriesAfterSequence(tx *sql.Tx, afterSequence uint64, limit int) ([]*types.CommitStatusDelivery, error) {
	q := commitStatusDeliverySelect().OrderBy("sequence").Asc()
	q.Where(q.G("sequence", afterSequence))

	if limit > 0 {
		q.Limit(limit)
	}

	commitStatusDeliveries, _, err := d.fetchCommitStatusDeliverys(tx, q)
	return commitStatusDeliveries, errors.WithStack(err)
}

func (d *DB) GetCommitStatusDeliveryByID(tx *sql.Tx, commitStatusDeliveryID string) (*types.CommitStatusDelivery, error) {
	q := commitStatusDeliverySelect()
	q.Where(q.E("id", commitStatusDeliveryID))
	commitStatusDeliveries, _, err := d.fetchCommitStatusDeliverys(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(commitStatusDeliveries)
	return out, errors.WithStack(err)
}

func (d *DB) GetCommitStatusByID(tx *sql.Tx, commitStatusID string) (*types.CommitStatus, error) {
	q := commitStatusSelect()
	q.Where(q.E("id", commitStatusID))
	commitStatuses, _, err := d.fetchCommitStatuss(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(commitStatuses)
	return out, errors.WithStack(err)
}

func (d *DB) GetCommitStatuses(tx *sql.Tx, limit int) ([]*types.CommitStatus, error) {
	q := commitStatusSelect()
	if limit > 0 {
		q.Limit(limit)
	}
	commitStatuses, _, err := d.fetchCommitStatuss(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return commitStatuses, errors.WithStack(err)
}

func (d *DB) GetCommitStatusesAfterCommitStatusID(tx *sql.Tx, afterCommitStatusID string, limit int) ([]*types.CommitStatus, error) {
	q := commitStatusSelect().OrderBy("id")
	if afterCommitStatusID != "" {
		q.Where(q.G("id", afterCommitStatusID))
	}

	if limit > 0 {
		q.Limit(limit)
	}
	commitStatuses, _, err := d.fetchCommitStatuss(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return commitStatuses, errors.WithStack(err)
}

func (d *DB) GetProjectCommitStatusDeliveriesAfterSequenceByProjectID(tx *sql.Tx, afterSequence uint64, projectID string, deliveryStatusFilter []types.DeliveryStatus, limit int, sortDirection types.SortDirection) ([]*types.CommitStatusDelivery, error) {
	q := commitStatusDeliverySelect().OrderBy("sequence")

	if projectID != "" {
		q.Join("commitstatus", "commitstatus.id = commitstatusdelivery.commit_status_id")
		q.Where(q.E("commitstatus.project_id", projectID))
	}
	if len(deliveryStatusFilter) > 0 {
		q.Where(q.In("delivery_status", sq.Flatten(deliveryStatusFilter)...))
	}

	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}
	if afterSequence > 0 {
		switch sortDirection {
		case types.SortDirectionAsc:
			q.Where(q.G("sequence", afterSequence))
		case types.SortDirectionDesc:
			q.Where(q.L("sequence", afterSequence))
		}
	}

	if limit > 0 {
		q.Limit(limit)
	}

	commitStatusDeliveries, _, err := d.fetchCommitStatusDeliverys(tx, q)
	return commitStatusDeliveries, errors.WithStack(err)
}

func (d *DB) GetCommitStatusDeliveriesByCommitStatusID(tx *sql.Tx, commitStatusID string, deliveryStatusFilter []types.DeliveryStatus, limit int, sortDirection types.SortDirection) ([]*types.CommitStatusDelivery, error) {
	q := commitStatusDeliverySelect().OrderBy("sequence")
	q.Where(q.E("commit_status_id", commitStatusID))

	if len(deliveryStatusFilter) > 0 {
		q.Where(q.In("delivery_status", sq.Flatten(deliveryStatusFilter)...))
	}

	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}

	if limit > 0 {
		q.Limit(limit)
	}

	commitStatusDeliveries, _, err := d.fetchCommitStatusDeliverys(tx, q)
	return commitStatusDeliveries, errors.WithStack(err)
}

func (d *DB) DeleteCommitStatusDeliveriesByCommitStatusID(tx *sql.Tx, commitStatusID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("commitstatusdelivery")
	q.Where(q.E("commit_status_id", commitStatusID))

	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete commitStatus deliveries")
	}

	return nil
}
