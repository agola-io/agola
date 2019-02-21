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

package readdb

import (
	"database/sql"
	"encoding/json"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
)

var (
	remotesourceSelect = sb.Select("id", "data").From("remotesource")
	remotesourceInsert = sb.Insert("remotesource").Columns("id", "name", "data")
)

func (r *ReadDB) insertRemoteSource(tx *db.Tx, data []byte) error {
	remoteSource := types.RemoteSource{}
	if err := json.Unmarshal(data, &remoteSource); err != nil {
		return errors.Wrap(err, "failed to unmarshal remotesource")
	}
	// poor man insert or update...
	if err := r.deleteRemoteSource(tx, remoteSource.ID); err != nil {
		return err
	}
	q, args, err := remotesourceInsert.Values(remoteSource.ID, remoteSource.Name, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	_, err = tx.Exec(q, args...)
	return errors.Wrap(err, "failed to insert remotesource")
}

func (r *ReadDB) deleteRemoteSource(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from remotesource where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete remotesource")
	}
	return nil
}

func (r *ReadDB) GetRemoteSource(tx *db.Tx, remoteSourceID string) (*types.RemoteSource, error) {
	q, args, err := remotesourceSelect.Where(sq.Eq{"id": remoteSourceID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	remoteSources, _, err := fetchRemoteSources(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(remoteSources) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(remoteSources) == 0 {
		return nil, nil
	}
	return remoteSources[0], nil
}

func (r *ReadDB) GetRemoteSourceByName(tx *db.Tx, name string) (*types.RemoteSource, error) {
	q, args, err := remotesourceSelect.Where(sq.Eq{"name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	remoteSources, _, err := fetchRemoteSources(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(remoteSources) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(remoteSources) == 0 {
		return nil, nil
	}
	return remoteSources[0], nil
}

func getRemoteSourcesFilteredQuery(startRemoteSourceName string, limit int, asc bool) sq.SelectBuilder {
	fields := []string{"id", "data"}

	s := sb.Select(fields...).From("remotesource as remotesource")
	if asc {
		s = s.OrderBy("remotesource.name asc")
	} else {
		s = s.OrderBy("remotesource.name desc")
	}
	if startRemoteSourceName != "" {
		if asc {
			s = s.Where(sq.Gt{"remotesource.name": startRemoteSourceName})
		} else {
			s = s.Where(sq.Lt{"remotesource.name": startRemoteSourceName})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	return s
}
func (r *ReadDB) GetRemoteSources(startRemoteSourceName string, limit int, asc bool) ([]*types.RemoteSource, error) {
	var remoteSources []*types.RemoteSource

	s := getRemoteSourcesFilteredQuery(startRemoteSourceName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	err = r.rdb.Do(func(tx *db.Tx) error {
		rows, err := tx.Query(q, args...)
		if err != nil {
			return err
		}

		remoteSources, _, err = scanRemoteSources(rows)
		return err
	})
	return remoteSources, errors.WithStack(err)
}

func fetchRemoteSources(tx *db.Tx, q string, args ...interface{}) ([]*types.RemoteSource, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanRemoteSources(rows)
}

func scanRemoteSource(rows *sql.Rows, additionalFields ...interface{}) (*types.RemoteSource, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Wrap(err, "failed to scan rows")
	}
	remoteSource := types.RemoteSource{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &remoteSource); err != nil {
			return nil, "", errors.Wrap(err, "failed to unmarshal remotesource")
		}
	}

	return &remoteSource, id, nil
}

func scanRemoteSources(rows *sql.Rows) ([]*types.RemoteSource, []string, error) {
	remoteSources := []*types.RemoteSource{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanRemoteSource(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		remoteSources = append(remoteSources, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return remoteSources, ids, nil
}
