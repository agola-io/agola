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
	orgSelect = sb.Select("org.id", "org.data").From("org")
	orgInsert = sb.Insert("org").Columns("id", "name", "data")
)

func (r *ReadDB) insertOrg(tx *db.Tx, data []byte) error {
	org := types.Organization{}
	if err := json.Unmarshal(data, &org); err != nil {
		return errors.Wrap(err, "failed to unmarshal org")
	}
	r.log.Infof("inserting org: %s", util.Dump(org))
	// poor man insert or update...
	if err := r.deleteOrg(tx, org.ID); err != nil {
		return err
	}
	q, args, err := orgInsert.Values(org.ID, org.Name, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return errors.Wrap(err, "failed to insert org")
	}

	return nil
}

func (r *ReadDB) deleteOrg(tx *db.Tx, orgID string) error {
	if _, err := tx.Exec("delete from org where id = $1", orgID); err != nil {
		return errors.Wrap(err, "failed to delete org")
	}
	return nil
}

func (r *ReadDB) GetOrg(tx *db.Tx, orgID string) (*types.Organization, error) {
	q, args, err := orgSelect.Where(sq.Eq{"id": orgID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	orgs, _, err := fetchOrgs(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(orgs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(orgs) == 0 {
		return nil, nil
	}
	return orgs[0], nil
}

func (r *ReadDB) GetOrgByName(tx *db.Tx, name string) (*types.Organization, error) {
	q, args, err := orgSelect.Where(sq.Eq{"name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	orgs, _, err := fetchOrgs(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(orgs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(orgs) == 0 {
		return nil, nil
	}
	return orgs[0], nil
}

func getOrgsFilteredQuery(startOrgName string, limit int, asc bool) sq.SelectBuilder {
	fields := []string{"id", "data"}

	s := sb.Select(fields...).From("org as org")
	if asc {
		s = s.OrderBy("org.name asc")
	} else {
		s = s.OrderBy("org.name desc")
	}
	if startOrgName != "" {
		if asc {
			s = s.Where(sq.Gt{"org.name": startOrgName})
		} else {
			s = s.Where(sq.Lt{"org.name": startOrgName})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	return s
}

func (r *ReadDB) GetOrgs(tx *db.Tx, startOrgName string, limit int, asc bool) ([]*types.Organization, error) {
	var orgs []*types.Organization

	s := getOrgsFilteredQuery(startOrgName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}

	orgs, _, err = scanOrgs(rows)
	return orgs, err
}

func fetchOrgs(tx *db.Tx, q string, args ...interface{}) ([]*types.Organization, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanOrgs(rows)
}

func scanOrg(rows *sql.Rows, additionalFields ...interface{}) (*types.Organization, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Wrap(err, "failed to scan rows")
	}
	org := types.Organization{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &org); err != nil {
			return nil, "", errors.Wrap(err, "failed to unmarshal org")
		}
	}

	return &org, id, nil
}

func scanOrgs(rows *sql.Rows) ([]*types.Organization, []string, error) {
	orgs := []*types.Organization{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanOrg(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		orgs = append(orgs, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return orgs, ids, nil
}
