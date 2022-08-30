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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetSecret(ctx context.Context, secretID string) (*types.Secret, error) {
	var secret *types.Secret
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		secret, err = h.d.GetSecretByID(tx, secretID)
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

func (h *ActionHandler) GetSecrets(ctx context.Context, parentKind types.ObjectKind, parentRef string, tree bool) ([]*types.Secret, error) {
	var secrets []*types.Secret
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, parentKind, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if tree {
			secrets, err = h.d.GetSecretsTree(tx, parentKind, parentID)
		} else {
			secrets, err = h.d.GetSecrets(tx, parentID)
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
	if req.Parent.Kind == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret parent kind required"))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret parentid required"))
	}
	if req.Parent.Kind != types.ObjectKindProject && req.Parent.Kind != types.ObjectKindProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret parent kind %q", req.Parent.Kind))
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

	var secret *types.Secret
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, req.Parent.Kind, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}

		req.Parent.ID = parentID

		// check duplicate secret name
		s, err := h.d.GetSecretByName(tx, parentID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if s != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID))
		}

		secret = types.NewSecret()
		secret.Name = req.Name
		secret.Parent = req.Parent
		secret.Type = req.Type
		secret.Data = req.Data
		secret.SecretProviderID = req.SecretProviderID
		secret.Path = req.Path

		if err := h.d.InsertSecret(tx, secret); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return secret, errors.WithStack(err)
}

func (h *ActionHandler) UpdateSecret(ctx context.Context, curSecretName string, req *CreateUpdateSecretRequest) (*types.Secret, error) {
	if err := h.ValidateSecretReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var secret *types.Secret
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, req.Parent.Kind, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}

		req.Parent.ID = parentID

		// check secret exists
		secret, err = h.d.GetSecretByName(tx, req.Parent.ID, curSecretName)
		if err != nil {
			return errors.WithStack(err)
		}
		if secret == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q doesn't exists", curSecretName, req.Parent.Kind, req.Parent.ID))
		}

		if secret.Name != req.Name {
			// check duplicate secret name
			s, err := h.d.GetSecretByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if s != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID))
			}
		}

		// update current secret
		secret.Name = req.Name
		secret.Parent = req.Parent
		secret.Type = req.Type
		secret.Data = req.Data
		secret.SecretProviderID = req.SecretProviderID
		secret.Path = req.Path

		if err := h.d.UpdateSecret(tx, secret); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return secret, errors.WithStack(err)
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentKind types.ObjectKind, parentRef, secretName string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, parentKind, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}

		// check secret existance
		secret, err := h.d.GetSecretByName(tx, parentID, secretName)
		if err != nil {
			return errors.WithStack(err)
		}
		if secret == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("secret with name %q doesn't exist", secretName))
		}

		if err := h.d.DeleteSecret(tx, secret.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
