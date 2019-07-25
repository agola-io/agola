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

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

const dbVersionTableDDLTmpl = `
	create table if not exists dbversion (version int not null, time timestamptz not null)
`

const dbVersion = 1

func (db *DB) Create(ctx context.Context, stmts []string) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	err := db.Do(ctx, func(tx *Tx) error {
		if _, err := tx.Exec(dbVersionTableDDLTmpl); err != nil {
			return errors.Errorf("failed to create dbversion table: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = db.Do(ctx, func(tx *Tx) error {
		var version sql.NullInt64
		q, args, err := sb.Select("max(version)").From("dbversion").ToSql()
		if err != nil {
			return err
		}
		if err := tx.QueryRow(q, args...).Scan(&version); err != nil {
			return errors.Errorf("cannot get current db version: %w", err)
		}
		if version.Valid {
			return nil
		}

		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt); err != nil {
				return errors.Errorf("creation failed: %w", err)
			}
		}

		q, args, err = sb.Insert("dbversion").Columns("version", "time").Values(dbVersion, "now()").ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Errorf("failed to update dbversion table: %w", err)
		}
		return nil
	})
	return err
}
