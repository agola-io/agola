// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package db

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
)

const dbVersionTableDDLTmpl = `
	create table if not exists dbversion (version int not null, time timestamptz not null)
`

const dbVersion = 1

func (db *DB) Create(stmts []string) error {
	sb := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	err := db.Do(func(tx *Tx) error {
		if _, err := tx.Exec(dbVersionTableDDLTmpl); err != nil {
			return errors.Wrap(err, "failed to create dbversion table")
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = db.Do(func(tx *Tx) error {
		var version sql.NullInt64
		q, args, err := sb.Select("max(version)").From("dbversion").ToSql()
		if err != nil {
			return err
		}
		if err := tx.QueryRow(q, args...).Scan(&version); err != nil {
			return errors.Wrap(err, "cannot get current db version")
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
			return err
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Wrap(err, "failed to update dbversion table")
		}
		return nil
	})
	return err
}
