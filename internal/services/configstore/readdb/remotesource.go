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

package readdb

import (
	"context"
	"database/sql"
	"encoding/json"

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

var (
	remotesourceSelect = sb.Select("id", "data").From("remotesource")
	remotesourceInsert = sb.Insert("remotesource").Columns("id", "name", "data")
)

func (r *ReadDB) insertRemoteSource(tx *db.Tx, data []byte) error {
	remoteSource := types.RemoteSource{}
	if err := json.Unmarshal(data, &remoteSource); err != nil {
		return errors.Errorf("failed to unmarshal remotesource: %w", err)
	}
	// poor man insert or update...
	if err := r.deleteRemoteSource(tx, remoteSource.ID); err != nil {
		return err
	}
	q, args, err := remotesourceInsert.Values(remoteSource.ID, remoteSource.Name, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert remotesource: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteRemoteSource(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from remotesource where id = $1", id); err != nil {
		return errors.Errorf("failed to delete remotesource: %w", err)
	}
	return nil
}

func (r *ReadDB) GetRemoteSource(tx *db.Tx, rsRef string) (*types.RemoteSource, error) {
	refType, err := common.ParseNameRef(rsRef)
	if err != nil {
		return nil, err
	}

	var rs *types.RemoteSource
	switch refType {
	case common.RefTypeID:
		rs, err = r.GetRemoteSourceByID(tx, rsRef)
	case common.RefTypeName:
		rs, err = r.GetRemoteSourceByName(tx, rsRef)
	}
	return rs, err
}

func (r *ReadDB) GetRemoteSourceByID(tx *db.Tx, remoteSourceID string) (*types.RemoteSource, error) {
	q, args, err := remotesourceSelect.Where(sq.Eq{"id": remoteSourceID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	remoteSources, _, err := fetchRemoteSources(tx, q, args...)
	if err != nil {
		return nil, err
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
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	remoteSources, _, err := fetchRemoteSources(tx, q, args...)
	if err != nil {
		return nil, err
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

func (r *ReadDB) GetRemoteSources(ctx context.Context, startRemoteSourceName string, limit int, asc bool) ([]*types.RemoteSource, error) {
	var remoteSources []*types.RemoteSource

	s := getRemoteSourcesFilteredQuery(startRemoteSourceName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	err = r.rdb.Do(ctx, func(tx *db.Tx) error {
		rows, err := tx.Query(q, args...)
		if err != nil {
			return err
		}

		remoteSources, _, err = scanRemoteSources(rows)
		return err
	})
	return remoteSources, err
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
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	remoteSource := types.RemoteSource{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &remoteSource); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal remotesource: %w", err)
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
