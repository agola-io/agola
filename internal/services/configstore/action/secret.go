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

package action

import (
	"context"
	"encoding/json"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/dbold"
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gofrs/uuid"
)

func (h *ActionHandler) GetSecret(ctx context.Context, secretID string) (*types.Secret, error) {
	var secret *types.Secret
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		secret, err = h.readDB.GetSecretByID(tx, secretID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if secret == nil {
		return nil, util.NewAPIError(util.ErrNotExist, errors.Errorf("secret %q doesn't exist", secretID))
	}

	return secret, nil
}

func (h *ActionHandler) GetSecrets(ctx context.Context, parentType types.ConfigType, parentRef string, tree bool) ([]*types.Secret, error) {
	var secrets []*types.Secret
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		parentID, err := h.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if tree {
			secrets, err = h.readDB.GetSecretsTree(tx, parentType, parentID)
		} else {
			secrets, err = h.readDB.GetSecrets(tx, parentID)
		}
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return secrets, nil
}

func (h *ActionHandler) ValidateSecretReq(ctx context.Context, req *CreateUpdateSecretRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret name required"))
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret name %q", req.Name))
	}
	if req.Type != types.SecretTypeInternal {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret type %q", req.Type))
	}
	switch req.Type {
	case types.SecretTypeInternal:
		if len(req.Data) == 0 {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty secret data"))
		}
	}
	if req.Parent.Type == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret parent type required"))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret parentid required"))
	}
	if req.Parent.Type != types.ConfigTypeProject && req.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret parent type %q", req.Parent.Type))
	}

	return nil
}

type CreateUpdateSecretRequest struct {
	Name             string
	Parent           types.Parent
	Type             types.SecretType
	Data             map[string]string
	SecretProviderID string
	Path             string
}

func (h *ActionHandler) CreateSecret(ctx context.Context, req *CreateUpdateSecretRequest) (*types.Secret, error) {
	if err := h.ValidateSecretReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the secret name
	cgNames := []string{util.EncodeSha256Hex("secretname-" + req.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		parentID, err := h.ResolveConfigID(tx, req.Parent.Type, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check duplicate secret name
		s, err := h.readDB.GetSecretByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if s != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Type, req.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	secret := &types.Secret{}
	secret.ID = uuid.Must(uuid.NewV4()).String()
	secret.Name = req.Name
	secret.Parent = req.Parent
	secret.Type = req.Type
	secret.Data = req.Data
	secret.SecretProviderID = req.SecretProviderID
	secret.Path = req.Path

	secretj, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal secret")
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
	return secret, errors.WithStack(err)
}

func (h *ActionHandler) UpdateSecret(ctx context.Context, curSecretName string, req *CreateUpdateSecretRequest) (*types.Secret, error) {
	if err := h.ValidateSecretReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the secret name

	var secret *types.Secret
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		parentID, err := h.ResolveConfigID(tx, req.Parent.Type, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check secret exists
		secret, err = h.readDB.GetSecretByName(tx, req.Parent.ID, curSecretName)
		if err != nil {
			return errors.WithStack(err)
		}
		if secret == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q doesn't exists", curSecretName, req.Parent.Type, req.Parent.ID))
		}

		if secret.Name != req.Name {
			// check duplicate secret name
			u, err := h.readDB.GetSecretByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if u != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Type, req.Parent.ID))
			}
		}

		// update current secret
		secret.Name = req.Name
		secret.Parent = req.Parent
		secret.Type = req.Type
		secret.Data = req.Data
		secret.SecretProviderID = req.SecretProviderID
		secret.Path = req.Path

		cgNames := []string{
			util.EncodeSha256Hex("secretname-" + secret.ID),
			util.EncodeSha256Hex("secretname-" + secret.Name),
		}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	secretj, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal secret")
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
	return secret, errors.WithStack(err)
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, secretName string) error {
	var secret *types.Secret

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		parentID, err := h.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}

		// check secret existance
		secret, err = h.readDB.GetSecretByName(tx, parentID, secretName)
		if err != nil {
			return errors.WithStack(err)
		}
		if secret == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q doesn't exist", secretName))
		}

		// changegroup is the secret id
		cgNames := []string{util.EncodeSha256Hex("secretid-" + secret.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeSecret),
			ID:         secret.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return errors.WithStack(err)
}
