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
	secretSelect = sb.Select("id", "data").From("secret")
	secretInsert = sb.Insert("secret").Columns("id", "name", "parentid", "data")
)

func (r *ReadDB) insertSecret(tx *db.Tx, data []byte) error {
	secret := types.Secret{}
	if err := json.Unmarshal(data, &secret); err != nil {
		return errors.Wrap(err, "failed to unmarshal secret")
	}
	// poor man insert or update...
	if err := r.deleteSecret(tx, secret.ID); err != nil {
		return err
	}
	q, args, err := secretInsert.Values(secret.ID, secret.Name, secret.Parent.ID, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	_, err = tx.Exec(q, args...)
	return errors.Wrap(err, "failed to insert secret")
}

func (r *ReadDB) deleteSecret(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from secret where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}
	return nil
}

func (r *ReadDB) GetSecretByID(tx *db.Tx, secretID string) (*types.Secret, error) {
	q, args, err := secretSelect.Where(sq.Eq{"id": secretID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
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
		return nil, errors.Wrap(err, "failed to build query")
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
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
		return nil, errors.Wrap(err, "failed to build query")
	}

	secrets, _, err := fetchSecrets(tx, q, args...)
	return secrets, err
}

func (r *ReadDB) GetSecretTree(tx *db.Tx, parentType types.ConfigType, parentID, name string) (*types.Secret, error) {
	for parentType == types.ConfigTypeProjectGroup || parentType == types.ConfigTypeProject {
		secret, err := r.GetSecretByName(tx, parentID, name)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secret with name %q", name)
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
			return nil, errors.Wrapf(err, "failed to get secrets for %s %q", parentType, parentID)
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
		return nil, "", errors.Wrap(err, "failed to scan rows")
	}
	secret := types.Secret{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &secret); err != nil {
			return nil, "", errors.Wrap(err, "failed to unmarshal secret")
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
