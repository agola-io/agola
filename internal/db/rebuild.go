package db

import (
	"context"
	"fmt"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/rs/zerolog"
)

func rebuild(ctx context.Context, log zerolog.Logger, d DB) error {
	// TODO(sgotti) handle concurrent rebuild locking
	// TODO(sgotti) implement rebuild restart points instead of a single mega transaction

	err := d.Do(ctx, func(tx *sql.Tx) error {
		for _, oi := range d.ObjectsInfo() {
			if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s_q", oi.Table)); err != nil {
				return errors.Wrapf(err, "failed to drop table %s", oi.Table)
			}

		}

		for _, stmt := range d.QTablesStatements() {
			if _, err := tx.Exec(stmt); err != nil {
				return errors.Wrap(err, "statement failed")
			}
		}

		for _, oi := range d.ObjectsInfo() {
			var curStartID string

			for {
				idEntry := fmt.Sprintf("%s.id", oi.Table)
				revisionEntry := fmt.Sprintf("%s.revision", oi.Table)
				dataEntry := fmt.Sprintf("%s.data", oi.Table)
				q := sb.Select(idEntry, revisionEntry, dataEntry).From(oi.Table).OrderBy("id asc")
				q = q.Where(sq.Gt{idEntry: curStartID})
				q = q.Limit(MaxQueryLimit)

				rows, err := d.Query(tx, q)
				if err != nil {
					return errors.WithStack(err)
				}

				datas := []ObjectData{}
				for rows.Next() {
					var id string
					var revision uint64
					var data []byte
					if err := rows.Scan(&id, &revision, &data); err != nil {
						rows.Close()
						return errors.Wrap(err, "failed to scan rows")
					}
					datas = append(datas, ObjectData{
						id:       id,
						revision: revision,
						data:     data,
					})
				}

				var lastID string
				for _, data := range datas {
					obj, err := d.UnmarshalObject(data.data)
					if err != nil {
						return errors.WithStack(err)
					}
					obj.SetRevision(data.revision)
					if err := d.InsertObjectQ(tx, obj, data.data); err != nil {
						return errors.WithStack(err)
					}
					lastID = data.id
				}

				if len(datas) < MaxQueryLimit {
					break
				}

				curStartID = lastID
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
