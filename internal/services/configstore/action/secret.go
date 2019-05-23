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

package action

import (
	"context"
	"encoding/json"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetSecret(ctx context.Context, secretID string) (*types.Secret, error) {
	var secret *types.Secret
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		secret, err = h.readDB.GetSecretByID(tx, secretID)
		return err
	})
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, util.NewErrNotFound(errors.Errorf("secret %q doesn't exist", secretID))
	}

	return secret, nil
}

func (h *ActionHandler) GetSecrets(ctx context.Context, parentType types.ConfigType, parentRef string, tree bool) ([]*types.Secret, error) {
	var secrets []*types.Secret
	err := h.readDB.Do(func(tx *db.Tx) error {
		parentID, err := h.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}
		if tree {
			secrets, err = h.readDB.GetSecretsTree(tx, parentType, parentID)
		} else {
			secrets, err = h.readDB.GetSecrets(tx, parentID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	return secrets, nil
}

func (h *ActionHandler) CreateSecret(ctx context.Context, secret *types.Secret) (*types.Secret, error) {
	if secret.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret name required"))
	}
	if !util.ValidateName(secret.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret name %q", secret.Name))
	}
	if secret.Type != types.SecretTypeInternal {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret type %q", secret.Type))
	}
	switch secret.Type {
	case types.SecretTypeInternal:
		if len(secret.Data) == 0 {
			return nil, util.NewErrBadRequest(errors.Errorf("empty secret data"))
		}
	}
	if secret.Parent.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret parent type required"))
	}
	if secret.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret parentid required"))
	}
	if secret.Parent.Type != types.ConfigTypeProject && secret.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret parent type %q", secret.Parent.Type))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the secret name
	cgNames := []string{util.EncodeSha256Hex("secretname-" + secret.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		parentID, err := h.readDB.ResolveConfigID(tx, secret.Parent.Type, secret.Parent.ID)
		if err != nil {
			return err
		}
		secret.Parent.ID = parentID

		// check duplicate secret name
		s, err := h.readDB.GetSecretByName(tx, secret.Parent.ID, secret.Name)
		if err != nil {
			return err
		}
		if s != nil {
			return util.NewErrBadRequest(errors.Errorf("secret with name %q for %s with id %q already exists", secret.Name, secret.Parent.Type, secret.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	secret.ID = uuid.NewV4().String()

	secretj, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Errorf("failed to marshal secret: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeSecret),
			ID:         secret.ID,
			Data:       secretj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return secret, err
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, secretName string) error {
	var secret *types.Secret

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		parentID, err := h.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}

		// check secret existance
		secret, err = h.readDB.GetSecretByName(tx, parentID, secretName)
		if err != nil {
			return err
		}
		if secret == nil {
			return util.NewErrBadRequest(errors.Errorf("secret with name %q doesn't exist", secretName))
		}

		// changegroup is the secret id
		cgNames := []string{util.EncodeSha256Hex("secretid-" + secret.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeSecret),
			ID:         secret.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
