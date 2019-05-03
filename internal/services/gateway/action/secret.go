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
	"net/http"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/pkg/errors"
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
		return nil, errors.Wrapf(err, "failed to determine ownership")
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
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create secret"))
	}
	h.log.Infof("secret %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

func (h *ActionHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, name string) error {
	isVariableOwner, err := h.IsVariableOwner(ctx, parentType, parentRef)
	if err != nil {
		return errors.Wrapf(err, "failed to determine ownership")
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
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to delete secret"))
	}
	return nil
}
