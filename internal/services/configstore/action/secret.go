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
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetSecret(ctx context.Context, secretID string) (*types.Secret, error) {
	var secret *types.Secret
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		secret, err = h.readDB.GetSecretByID(tx, secretID)
		return err
	})
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, util.NewErrNotExist(errors.Errorf("secret %q doesn't exist", secretID))
	}

	return secret, nil
}

func (h *ActionHandler) GetSecrets(ctx context.Context, parentType types.ConfigType, parentRef string, tree bool) ([]*types.Secret, error) {
	var secrets []*types.Secret
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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

func (h *ActionHandler) ValidateSecret(ctx context.Context, secret *types.Secret) error {
	if secret.Name == "" {
		return util.NewErrBadRequest(errors.Errorf("secret name required"))
	}
	if !util.ValidateName(secret.Name) {
		return util.NewErrBadRequest(errors.Errorf("invalid secret name %q", secret.Name))
	}
	if secret.Type != types.SecretTypeInternal {
		return util.NewErrBadRequest(errors.Errorf("invalid secret type %q", secret.Type))
	}
	switch secret.Type {
	case types.SecretTypeInternal:
		if len(secret.Data) == 0 {
			return util.NewErrBadRequest(errors.Errorf("empty secret data"))
		}
	}
	if secret.Parent.Type == "" {
		return util.NewErrBadRequest(errors.Errorf("secret parent type required"))
	}
	if secret.Parent.ID == "" {
		return util.NewErrBadRequest(errors.Errorf("secret parentid required"))
	}
	if secret.Parent.Type != types.ConfigTypeProject && secret.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewErrBadRequest(errors.Errorf("invalid secret parent type %q", secret.Parent.Type))
	}

	return nil
}

func (h *ActionHandler) CreateSecret(ctx context.Context, secret *types.Secret) (*types.Secret, error) {
	if err := h.ValidateSecret(ctx, secret); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the secret name
	cgNames := []string{util.EncodeSha256Hex("secretname-" + secret.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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

type UpdateSecretRequest struct {
	SecretName string

	Secret *types.Secret
}

func (h *ActionHandler) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*types.Secret, error) {
	if err := h.ValidateSecret(ctx, req.Secret); err != nil {
		return nil, err
	}

	var curSecret *types.Secret
	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the secret name

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		parentID, err := h.readDB.ResolveConfigID(tx, req.Secret.Parent.Type, req.Secret.Parent.ID)
		if err != nil {
			return err
		}
		req.Secret.Parent.ID = parentID

		// check secret exists
		curSecret, err = h.readDB.GetSecretByName(tx, req.Secret.Parent.ID, req.SecretName)
		if err != nil {
			return err
		}
		if curSecret == nil {
			return util.NewErrBadRequest(errors.Errorf("secret with name %q for %s with id %q doesn't exists", req.SecretName, req.Secret.Parent.Type, req.Secret.Parent.ID))
		}

		if curSecret.Name != req.Secret.Name {
			// check duplicate secret name
			u, err := h.readDB.GetSecretByName(tx, req.Secret.Parent.ID, req.Secret.Name)
			if err != nil {
				return err
			}
			if u != nil {
				return util.NewErrBadRequest(errors.Errorf("secret with name %q for %s with id %q already exists", req.Secret.Name, req.Secret.Parent.Type, req.Secret.Parent.ID))
			}
		}

		// set/override ID that must be kept from the current secret
		req.Secret.ID = curSecret.ID

		cgNames := []string{
			util.EncodeSha256Hex("secretname-" + req.Secret.ID),
			util.EncodeSha256Hex("secretname-" + req.Secret.Name),
		}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	secretj, err := json.Marshal(req.Secret)
	if err != nil {
		return nil, errors.Errorf("failed to marshal secret: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeSecret),
			ID:         req.Secret.ID,
			Data:       secretj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return req.Secret, err
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, secretName string) error {
	var secret *types.Secret

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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
