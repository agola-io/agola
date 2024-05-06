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

	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetSecretTree(tx *sql.Tx, parentKind types.ObjectKind, parentID, name string) (*types.Secret, error) {
	for parentKind == types.ObjectKindProjectGroup || parentKind == types.ObjectKindProject {
		secret, err := h.d.GetSecretByName(tx, parentID, name)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secret with name %q", name)
		}
		if secret != nil {
			return secret, nil
		}

		switch parentKind {
		case types.ObjectKindProjectGroup:
			projectGroup, err := h.GetProjectGroupByRef(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentKind = projectGroup.Parent.Kind
			parentID = projectGroup.Parent.ID
		case types.ObjectKindProject:
			project, err := h.GetProjectByRef(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentKind = project.Parent.Kind
			parentID = project.Parent.ID
		}
	}

	return nil, nil
}

func (h *ActionHandler) GetSecretsTree(tx *sql.Tx, parentKind types.ObjectKind, parentID string) ([]*types.Secret, error) {
	allSecrets := []*types.Secret{}

	for parentKind == types.ObjectKindProjectGroup || parentKind == types.ObjectKindProject {
		secrets, err := h.d.GetSecrets(tx, parentID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secrets for %s %q", parentKind, parentID)
		}
		allSecrets = append(allSecrets, secrets...)

		switch parentKind {
		case types.ObjectKindProjectGroup:
			projectGroup, err := h.GetProjectGroupByRef(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentKind = projectGroup.Parent.Kind
			parentID = projectGroup.Parent.ID
		case types.ObjectKindProject:
			project, err := h.GetProjectByRef(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentKind = project.Parent.Kind
			parentID = project.Parent.ID
		}
	}

	return allSecrets, nil
}

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
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("secret %q doesn't exist", secretID), serrors.SecretDoesNotExist())
	}

	return secret, nil
}

type GetSecretsResponse struct {
	Secrets     []*types.Secret
	ParentPaths map[string]string
}

func (h *ActionHandler) GetSecrets(ctx context.Context, parentKind types.ObjectKind, parentRef string, tree bool) (*GetSecretsResponse, error) {
	var secrets []*types.Secret
	parentPaths := map[string]string{}
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, parentKind, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if tree {
			secrets, err = h.GetSecretsTree(tx, parentKind, parentID)
		} else {
			secrets, err = h.d.GetSecrets(tx, parentID)
		}
		if err != nil {
			return errors.WithStack(err)
		}

		// populate secrets parent paths
		for _, s := range secrets {
			pp, err := h.GetPath(tx, s.Parent.Kind, s.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			parentPaths[s.ID] = pp
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GetSecretsResponse{
		Secrets:     secrets,
		ParentPaths: parentPaths,
	}, nil
}

func (h *ActionHandler) ValidateSecretReq(ctx context.Context, req *CreateUpdateSecretRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("secret name required"), serrors.InvalidSecretName())
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid secret name %q", req.Name), serrors.InvalidSecretName())
	}
	if req.Type != types.SecretTypeInternal {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid secret type %q", req.Type), serrors.InvalidSecretType())
	}
	switch req.Type {
	case types.SecretTypeInternal:
		if len(req.Data) == 0 {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty secret data"), serrors.InvalidSecretData())
		}
	}
	if req.Parent.Kind == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("secret parent kind required"))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("secret parentid required"))
	}
	if req.Parent.Kind != types.ObjectKindProject && req.Parent.Kind != types.ObjectKindProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid secret parent kind %q", req.Parent.Kind))
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
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID), serrors.SecretAlreadyExists())
		}

		secret = types.NewSecret(tx)
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
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("secret with name %q for %s with id %q doesn't exists", curSecretName, req.Parent.Kind, req.Parent.ID), serrors.SecretDoesNotExist())
		}

		if secret.Name != req.Name {
			// check duplicate secret name
			s, err := h.d.GetSecretByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if s != nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("secret with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID), serrors.SecretAlreadyExists())
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
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("secret with name %q doesn't exist", secretName), serrors.SecretDoesNotExist())
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
