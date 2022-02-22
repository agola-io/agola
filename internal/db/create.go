// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"context"
	"database/sql"

	"agola.io/agola/internal/errors"
	sq "github.com/Masterminds/squirrel"
)

const dbVersionTableDDLTmpl = `
	create table if not exists dbversion (version int not null, time timestamptz not null)
`

const dbVersion = 1

func (db *DB) Create(ctx context.Context, stmts []string) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	err := db.Do(ctx, func(tx *Tx) error {
		if _, err := tx.Exec(dbVersionTableDDLTmpl); err != nil {
			return errors.Wrapf(err, "failed to create dbversion table")
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	err = db.Do(ctx, func(tx *Tx) error {
		var version sql.NullInt64
		q, args, err := sb.Select("max(version)").From("dbversion").ToSql()
		if err != nil {
			return errors.WithStack(err)
		}
		if err := tx.QueryRow(q, args...).Scan(&version); err != nil {
			return errors.Wrapf(err, "cannot get current db version")
		}
		if version.Valid {
			return nil
		}

		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt); err != nil {
				return errors.Wrapf(err, "creation failed")
			}
		}

		q, args, err = sb.Insert("dbversion").Columns("version", "time").Values(dbVersion, "now()").ToSql()
		if err != nil {
			return errors.WithStack(err)
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Wrapf(err, "failed to update dbversion table")
		}
		return nil
	})
	return errors.WithStack(err)
}
