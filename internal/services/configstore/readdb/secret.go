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
	secretSelect = sb.Select("id", "data").From("secret")
	secretInsert = sb.Insert("secret").Columns("id", "name", "parentid", "parenttype", "data")
)

func (r *ReadDB) insertSecret(tx *db.Tx, data []byte) error {
	secret := types.Secret{}
	if err := json.Unmarshal(data, &secret); err != nil {
		return errors.Errorf("failed to unmarshal secret: %w", err)
	}
	// poor man insert or update...
	if err := r.deleteSecret(tx, secret.ID); err != nil {
		return err
	}
	q, args, err := secretInsert.Values(secret.ID, secret.Name, secret.Parent.ID, secret.Parent.Type, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert secret: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteSecret(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from secret where id = $1", id); err != nil {
		return errors.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

func (r *ReadDB) GetSecretByID(tx *db.Tx, secretID string) (*types.Secret, error) {
	q, args, err := secretSelect.Where(sq.Eq{"id": secretID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(secrets) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(secrets) == 0 {
		return nil, nil
	}
	return secrets[0], nil
}

func (r *ReadDB) GetSecretByName(tx *db.Tx, parentID, name string) (*types.Secret, error) {
	q, args, err := secretSelect.Where(sq.Eq{"parentid": parentID, "name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(secrets) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(secrets) == 0 {
		return nil, nil
	}
	return secrets[0], nil
}

func (r *ReadDB) GetSecrets(tx *db.Tx, parentID string) ([]*types.Secret, error) {
	q, args, err := secretSelect.Where(sq.Eq{"parentid": parentID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	return secrets, err
}

func (r *ReadDB) GetSecretTree(tx *db.Tx, parentType types.ConfigType, parentID, name string) (*types.Secret, error) {
	for parentType == types.ConfigTypeProjectGroup || parentType == types.ConfigTypeProject {
		secret, err := r.GetSecretByName(tx, parentID, name)
		if err != nil {
			return nil, errors.Errorf("failed to get secret with name %q: %w", name, err)
		}
		if secret != nil {
			return secret, nil
		}

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

	return nil, nil
}

func (r *ReadDB) GetSecretsTree(tx *db.Tx, parentType types.ConfigType, parentID string) ([]*types.Secret, error) {
	allSecrets := []*types.Secret{}

	for parentType == types.ConfigTypeProjectGroup || parentType == types.ConfigTypeProject {
		secrets, err := r.GetSecrets(tx, parentID)
		if err != nil {
			return nil, errors.Errorf("failed to get secrets for %s %q: %w", parentType, parentID, err)
		}
		allSecrets = append(allSecrets, secrets...)

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

	return allSecrets, nil
}

func fetchSecrets(tx *db.Tx, q string, args ...interface{}) ([]*types.Secret, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanSecrets(rows)
}

func scanSecret(rows *sql.Rows, additionalFields ...interface{}) (*types.Secret, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	secret := types.Secret{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &secret); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal secret: %w", err)
		}
	}

	return &secret, id, nil
}

func scanSecrets(rows *sql.Rows) ([]*types.Secret, []string, error) {
	secrets := []*types.Secret{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanSecret(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		secrets = append(secrets, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return secrets, ids, nil
}
