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
	"database/sql"
	"encoding/json"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
)

var (
	projectSelect = sb.Select("id", "data").From("project")
	projectInsert = sb.Insert("project").Columns("id", "name", "ownerid", "data")
)

func (r *ReadDB) insertProject(tx *db.Tx, data []byte) error {
	project := types.Project{}
	if err := json.Unmarshal(data, &project); err != nil {
		return errors.Wrap(err, "failed to unmarshal project")
	}
	// poor man insert or update...
	if err := r.deleteProject(tx, project.ID); err != nil {
		return err
	}
	q, args, err := projectInsert.Values(project.ID, project.Name, project.OwnerID, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	_, err = tx.Exec(q, args...)
	return errors.Wrap(err, "failed to insert project")
}

func (r *ReadDB) deleteProject(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from project where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete project")
	}
	return nil
}

func (r *ReadDB) GetProject(tx *db.Tx, projectID string) (*types.Project, error) {
	q, args, err := projectSelect.Where(sq.Eq{"id": projectID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	projects, _, err := fetchProjects(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
}

func (r *ReadDB) GetOwnerProjectByName(tx *db.Tx, ownerid, name string) (*types.Project, error) {
	q, args, err := projectSelect.Where(sq.Eq{"ownerid": ownerid, "name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	projects, _, err := fetchProjects(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
}

func getProjectsFilteredQuery(ownerid, startProjectName string, limit int, asc bool) sq.SelectBuilder {
	fields := []string{"id", "data"}

	s := sb.Select(fields...).From("project as project")
	if asc {
		s = s.OrderBy("project.name asc")
	} else {
		s = s.OrderBy("project.name desc")
	}
	if ownerid != "" {
		s = s.Where(sq.Eq{"project.ownerid": ownerid})
	}
	if startProjectName != "" {
		if asc {
			s = s.Where(sq.Gt{"project.name": startProjectName})
		} else {
			s = s.Where(sq.Lt{"project.name": startProjectName})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	return s
}

func (r *ReadDB) GetOwnerProjects(tx *db.Tx, ownerid, startProjectName string, limit int, asc bool) ([]*types.Project, error) {
	var projects []*types.Project

	s := getProjectsFilteredQuery(ownerid, startProjectName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}

	projects, _, err = scanProjects(rows)
	return projects, err
}

func (r *ReadDB) GetProjects(tx *db.Tx, startProjectName string, limit int, asc bool) ([]*types.Project, error) {
	var projects []*types.Project

	s := getProjectsFilteredQuery("", startProjectName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}

	projects, _, err = scanProjects(rows)
	return projects, err
}

func fetchProjects(tx *db.Tx, q string, args ...interface{}) ([]*types.Project, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanProjects(rows)
}

func scanProject(rows *sql.Rows, additionalFields ...interface{}) (*types.Project, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Wrap(err, "failed to scan rows")
	}
	project := types.Project{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &project); err != nil {
			return nil, "", errors.Wrap(err, "failed to unmarshal project")
		}
	}

	return &project, id, nil
}

func scanProjects(rows *sql.Rows) ([]*types.Project, []string, error) {
	projects := []*types.Project{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanProject(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		projects = append(projects, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return projects, ids, nil
}
