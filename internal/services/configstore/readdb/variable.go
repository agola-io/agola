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

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

var (
	variableSelect = sb.Select("id", "data").From("variable")
	variableInsert = sb.Insert("variable").Columns("id", "name", "parentid", "parenttype", "data")
)

func (r *ReadDB) insertVariable(tx *db.Tx, data []byte) error {
	variable := types.Variable{}
	if err := json.Unmarshal(data, &variable); err != nil {
		return errors.Errorf("failed to unmarshal variable: %w", err)
	}
	// poor man insert or update...
	if err := r.deleteVariable(tx, variable.ID); err != nil {
		return err
	}
	q, args, err := variableInsert.Values(variable.ID, variable.Name, variable.Parent.ID, variable.Parent.Type, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert variable: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteVariable(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from variable where id = $1", id); err != nil {
		return errors.Errorf("failed to delete variable: %w", err)
	}
	return nil
}

func (r *ReadDB) GetVariableByID(tx *db.Tx, variableID string) (*types.Variable, error) {
	q, args, err := variableSelect.Where(sq.Eq{"id": variableID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	variables, _, err := fetchVariables(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(variables) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(variables) == 0 {
		return nil, nil
	}
	return variables[0], nil
}

func (r *ReadDB) GetVariableByName(tx *db.Tx, parentID, name string) (*types.Variable, error) {
	q, args, err := variableSelect.Where(sq.Eq{"parentid": parentID, "name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	variables, _, err := fetchVariables(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(variables) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(variables) == 0 {
		return nil, nil
	}
	return variables[0], nil
}

func (r *ReadDB) GetVariables(tx *db.Tx, parentID string) ([]*types.Variable, error) {
	q, args, err := variableSelect.Where(sq.Eq{"parentid": parentID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	variables, _, err := fetchVariables(tx, q, args...)
	return variables, err
}

func (r *ReadDB) GetVariablesTree(tx *db.Tx, parentType types.ConfigType, parentID string) ([]*types.Variable, error) {
	allVariables := []*types.Variable{}

	for parentType == types.ConfigTypeProjectGroup || parentType == types.ConfigTypeProject {
		vars, err := r.GetVariables(tx, parentID)
		if err != nil {
			return nil, errors.Errorf("failed to get variables for %s %q: %w", parentType, parentID, err)
		}
		allVariables = append(allVariables, vars...)

		switch parentType {
		case types.ConfigTypeProjectGroup:
			projectGroup, err := r.GetProjectGroup(tx, parentID)
			if err != nil {
				return nil, err
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentType = projectGroup.Parent.Type
			parentID = projectGroup.Parent.ID
		case types.ConfigTypeProject:
			project, err := r.GetProject(tx, parentID)
			if err != nil {
				return nil, err
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentType = project.Parent.Type
			parentID = project.Parent.ID
		}
	}

	return allVariables, nil
}

func fetchVariables(tx *db.Tx, q string, args ...interface{}) ([]*types.Variable, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanVariables(rows)
}

func scanVariable(rows *sql.Rows, additionalFields ...interface{}) (*types.Variable, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	variable := types.Variable{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &variable); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal variable: %w", err)
		}
	}

	return &variable, id, nil
}

func scanVariables(rows *sql.Rows) ([]*types.Variable, []string, error) {
	variables := []*types.Variable{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanVariable(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		variables = append(variables, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return variables, ids, nil
}
