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
	variableSelect = sb.Select("id", "data").From("variable")
	variableInsert = sb.Insert("variable").Columns("id", "name", "parentid", "data")
)

func (r *ReadDB) insertVariable(tx *db.Tx, data []byte) error {
	variable := types.Variable{}
	if err := json.Unmarshal(data, &variable); err != nil {
		return errors.Wrap(err, "failed to unmarshal variable")
	}
	// poor man insert or update...
	if err := r.deleteVariable(tx, variable.ID); err != nil {
		return err
	}
	q, args, err := variableInsert.Values(variable.ID, variable.Name, variable.Parent.ID, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	_, err = tx.Exec(q, args...)
	return errors.Wrap(err, "failed to insert variable")
}

func (r *ReadDB) deleteVariable(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from variable where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete variable")
	}
	return nil
}

func (r *ReadDB) GetVariableByID(tx *db.Tx, variableID string) (*types.Variable, error) {
	q, args, err := variableSelect.Where(sq.Eq{"id": variableID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	variables, _, err := fetchVariables(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
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
		return nil, errors.Wrap(err, "failed to build query")
	}

	variables, _, err := fetchVariables(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
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
		return nil, errors.Wrap(err, "failed to build query")
	}

	variables, _, err := fetchVariables(tx, q, args...)
	return variables, err
}

func (r *ReadDB) GetVariablesTree(tx *db.Tx, parentType types.ConfigType, parentID string) ([]*types.Variable, error) {
	allVariables := []*types.Variable{}

	for parentType == types.ConfigTypeProjectGroup || parentType == types.ConfigTypeProject {
		vars, err := r.GetVariables(tx, parentID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get variables for %s %q", parentType, parentID)
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
		return nil, "", errors.Wrap(err, "failed to scan rows")
	}
	variable := types.Variable{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &variable); err != nil {
			return nil, "", errors.Wrap(err, "failed to unmarshal variable")
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
