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

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	errors "golang.org/x/xerrors"
)

type GetSecretsRequest struct {
	ParentType cstypes.ConfigType
	ParentRef  string

	Tree             bool
	RemoveOverridden bool
}

func (h *ActionHandler) GetSecrets(ctx context.Context, req *GetSecretsRequest) ([]*csapitypes.Secret, error) {
	var cssecrets []*csapitypes.Secret
	var err error
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		cssecrets, _, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, req.Tree)
	case cstypes.ConfigTypeProject:
		cssecrets, _, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, req.Tree)
	}
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	if req.RemoveOverridden {
		// remove overriden secrets
		cssecrets = common.FilterOverriddenSecrets(cssecrets)
	}

	return cssecrets, nil
}

type CreateSecretRequest struct {
	Name string

	ParentType cstypes.ConfigType
	ParentRef  string

	Type cstypes.SecretType

	// internal secret
	Data map[string]string

	// external secret
	SecretProviderID string
	Path             string
}

func (h *ActionHandler) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*csapitypes.Secret, error) {
	isVariableOwner, err := h.IsVariableOwner(ctx, req.ParentType, req.ParentRef)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret name %q", req.Name))
	}

	s := &cstypes.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	var rs *csapitypes.Secret
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Info().Msgf("creating project group secret")
		rs, _, err = h.configstoreClient.CreateProjectGroupSecret(ctx, req.ParentRef, s)
	case cstypes.ConfigTypeProject:
		h.log.Info().Msgf("creating project secret")
		rs, _, err = h.configstoreClient.CreateProjectSecret(ctx, req.ParentRef, s)
	}
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create secret: %w", err))
	}
	h.log.Info().Msgf("secret %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

type UpdateSecretRequest struct {
	SecretName string

	Name string

	ParentType cstypes.ConfigType
	ParentRef  string

	Type cstypes.SecretType

	// internal secret
	Data map[string]string

	// external secret
	SecretProviderID string
	Path             string
}

func (h *ActionHandler) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*csapitypes.Secret, error) {
	isVariableOwner, err := h.IsVariableOwner(ctx, req.ParentType, req.ParentRef)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid secret name %q", req.Name))
	}

	s := &cstypes.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	var rs *csapitypes.Secret
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Info().Msgf("updating project group secret")
		rs, _, err = h.configstoreClient.UpdateProjectGroupSecret(ctx, req.ParentRef, req.SecretName, s)
	case cstypes.ConfigTypeProject:
		h.log.Info().Msgf("updating project secret")
		rs, _, err = h.configstoreClient.UpdateProjectSecret(ctx, req.ParentRef, req.SecretName, s)
	}
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to update secret: %w", err))
	}
	h.log.Info().Msgf("secret %s updated, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType cstypes.ConfigType, parentRef, name string) error {
	isVariableOwner, err := h.IsVariableOwner(ctx, parentType, parentRef)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	switch parentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Info().Msgf("deleting project group secret")
		_, err = h.configstoreClient.DeleteProjectGroupSecret(ctx, parentRef, name)
	case cstypes.ConfigTypeProject:
		h.log.Info().Msgf("deleting project secret")
		_, err = h.configstoreClient.DeleteProjectSecret(ctx, parentRef, name)
	}
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to delete secret: %w", err))
	}
	return nil
}
