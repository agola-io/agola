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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	errors "golang.org/x/xerrors"
)

type GetSecretsRequest struct {
	ParentType types.ConfigType
	ParentRef  string

	Tree bool
}

func (h *ActionHandler) GetSecrets(ctx context.Context, req *GetSecretsRequest) ([]*csapi.Secret, error) {
	var cssecrets []*csapi.Secret
	var resp *http.Response
	var err error
	switch req.ParentType {
	case types.ConfigTypeProjectGroup:
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, req.Tree)
	case types.ConfigTypeProject:
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, req.Tree)
	}
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	return cssecrets, nil
}

type CreateSecretRequest struct {
	Name string

	ParentType types.ConfigType
	ParentRef  string

	Type types.SecretType

	// internal secret
	Data map[string]string

	// external secret
	SecretProviderID string
	Path             string
}

type CreateSecretHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func (h *ActionHandler) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*csapi.Secret, error) {
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

	s := &types.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	var resp *http.Response
	var rs *csapi.Secret
	switch req.ParentType {
	case types.ConfigTypeProjectGroup:
		h.log.Infof("creating project group secret")
		rs, resp, err = h.configstoreClient.CreateProjectGroupSecret(ctx, req.ParentRef, s)
	case types.ConfigTypeProject:
		h.log.Infof("creating project secret")
		rs, resp, err = h.configstoreClient.CreateProjectSecret(ctx, req.ParentRef, s)
	}
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Errorf("failed to create secret: %w", err))
	}
	h.log.Infof("secret %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, name string) error {
	isVariableOwner, err := h.IsVariableOwner(ctx, parentType, parentRef)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	var resp *http.Response
	switch parentType {
	case types.ConfigTypeProjectGroup:
		h.log.Infof("deleting project group secret")
		resp, err = h.configstoreClient.DeleteProjectGroupSecret(ctx, parentRef, name)
	case types.ConfigTypeProject:
		h.log.Infof("deleting project secret")
		resp, err = h.configstoreClient.DeleteProjectSecret(ctx, parentRef, name)
	}
	if err != nil {
		return ErrFromRemote(resp, errors.Errorf("failed to delete secret: %w", err))
	}
	return nil
}
