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
	"path"
	"strings"

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

var (
	projectSelect = sb.Select("id", "data").From("project")
	projectInsert = sb.Insert("project").Columns("id", "name", "parentid", "parenttype", "data")
)

func (r *ReadDB) insertProject(tx *db.Tx, data []byte) error {
	var project *types.Project
	if err := json.Unmarshal(data, &project); err != nil {
		return errors.Errorf("failed to unmarshal project: %w", err)
	}
	// poor man insert or update...
	if err := r.deleteProject(tx, project.ID); err != nil {
		return err
	}
	q, args, err := projectInsert.Values(project.ID, project.Name, project.Parent.ID, project.Parent.Type, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert project: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteProject(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from project where id = $1", id); err != nil {
		return errors.Errorf("failed to delete project: %w", err)
	}
	return nil
}

func (r *ReadDB) GetProjectPath(tx *db.Tx, project *types.Project) (string, error) {
	pgroup, err := r.GetProjectGroup(tx, project.Parent.ID)
	if err != nil {
		return "", err
	}
	if pgroup == nil {
		return "", errors.Errorf("parent group %q for project %q doesn't exist", project.Parent.ID, project.ID)
	}
	p, err := r.GetProjectGroupPath(tx, pgroup)
	if err != nil {
		return "", err
	}

	p = path.Join(p, project.Name)

	return p, nil
}

func (r *ReadDB) GetProjectOwnerID(tx *db.Tx, project *types.Project) (types.ConfigType, string, error) {
	pgroup, err := r.GetProjectGroup(tx, project.Parent.ID)
	if err != nil {
		return "", "", err
	}
	if pgroup == nil {
		return "", "", errors.Errorf("parent group %q for project %q doesn't exist", project.Parent.ID, project.ID)
	}
	return r.GetProjectGroupOwnerID(tx, pgroup)
}

func (r *ReadDB) GetProject(tx *db.Tx, projectRef string) (*types.Project, error) {
	projectRefType, err := common.ParsePathRef(projectRef)
	if err != nil {
		return nil, err
	}

	var project *types.Project
	switch projectRefType {
	case common.RefTypeID:
		project, err = r.GetProjectByID(tx, projectRef)
	case common.RefTypePath:
		project, err = r.GetProjectByPath(tx, projectRef)
	}
	return project, err
}

func (r *ReadDB) GetProjectByID(tx *db.Tx, projectID string) (*types.Project, error) {
	q, args, err := projectSelect.Where(sq.Eq{"id": projectID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projects, _, err := fetchProjects(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
}

func (r *ReadDB) GetProjectByName(tx *db.Tx, parentID, name string) (*types.Project, error) {
	q, args, err := projectSelect.Where(sq.Eq{"parentid": parentID, "name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projects, _, err := fetchProjects(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
}

func (r *ReadDB) GetProjectByPath(tx *db.Tx, projectPath string) (*types.Project, error) {
	if len(strings.Split(projectPath, "/")) < 3 {
		return nil, errors.Errorf("wrong project path: %q", projectPath)
	}

	projectGroupPath := path.Dir(projectPath)
	projectName := path.Base(projectPath)
	projectGroup, err := r.GetProjectGroupByPath(tx, projectGroupPath)
	if err != nil {
		return nil, errors.Errorf("failed to get project group %q: %w", projectGroupPath, err)
	}
	if projectGroup == nil {
		return nil, nil
	}

	project, err := r.GetProjectByName(tx, projectGroup.ID, projectName)
	if err != nil {
		return nil, errors.Errorf("failed to get project group %q: %w", projectName, err)
	}
	return project, nil
}

func (r *ReadDB) GetProjectGroupProjects(tx *db.Tx, parentID string) ([]*types.Project, error) {
	var projects []*types.Project

	q, args, err := projectSelect.Where(sq.Eq{"parentid": parentID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projects, _, err = fetchProjects(tx, q, args...)
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
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	project := types.Project{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &project); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal project: %w", err)
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

// Test only functions

func (r *ReadDB) GetAllProjects(tx *db.Tx) ([]*types.Project, error) {
	var projects []*types.Project

	q, args, err := projectSelect.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projects, _, err = fetchProjects(tx, q, args...)
	return projects, err
}
