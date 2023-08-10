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

func (d *DB) GetRunWebhookDeliveriesAfterSequence(tx *sql.Tx, afterSequence uint64, deliveryStatus types.DeliveryStatus, limit int) ([]*types.RunWebhookDelivery, error) {
	q := runWebhookDeliverySelect().OrderBy("sequence").Asc()
	if deliveryStatus != "" {
		q.Where(q.E("delivery_status", deliveryStatus))
	}
	q.Where(q.G("sequence", afterSequence))

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
