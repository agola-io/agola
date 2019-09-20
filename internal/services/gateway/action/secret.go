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
	"net/http"

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
	var resp *http.Response
	var err error
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, req.Tree)
	case cstypes.ConfigTypeProject:
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, req.Tree)
	}
	if err != nil {
		return nil, ErrFromRemote(resp, err)
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
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret name %q", req.Name))
	}

	s := &cstypes.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	var resp *http.Response
	var rs *csapitypes.Secret
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Infof("creating project group secret")
		rs, resp, err = h.configstoreClient.CreateProjectGroupSecret(ctx, req.ParentRef, s)
	case cstypes.ConfigTypeProject:
		h.log.Infof("creating project secret")
		rs, resp, err = h.configstoreClient.CreateProjectSecret(ctx, req.ParentRef, s)
	}
	if err != nil {
		return nil, errors.Errorf("failed to create secret: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("secret %s created, ID: %s", rs.Name, rs.ID)

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
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret name %q", req.Name))
	}

	s := &cstypes.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	var resp *http.Response
	var rs *csapitypes.Secret
	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Infof("updating project group secret")
		rs, resp, err = h.configstoreClient.UpdateProjectGroupSecret(ctx, req.ParentRef, req.SecretName, s)
	case cstypes.ConfigTypeProject:
		h.log.Infof("updating project secret")
		rs, resp, err = h.configstoreClient.UpdateProjectSecret(ctx, req.ParentRef, req.SecretName, s)
	}
	if err != nil {
		return nil, errors.Errorf("failed to update secret: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("secret %s updated, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType cstypes.ConfigType, parentRef, name string) error {
	isVariableOwner, err := h.IsVariableOwner(ctx, parentType, parentRef)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	var resp *http.Response
	switch parentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Infof("deleting project group secret")
		resp, err = h.configstoreClient.DeleteProjectGroupSecret(ctx, parentRef, name)
	case cstypes.ConfigTypeProject:
		h.log.Infof("deleting project secret")
		resp, err = h.configstoreClient.DeleteProjectSecret(ctx, parentRef, name)
	}
	if err != nil {
		return errors.Errorf("failed to delete secret: %w", ErrFromRemote(resp, err))
	}
	return nil
}
