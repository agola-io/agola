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

	"github.com/sorintlab/agola/internal/services/common"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	errors "golang.org/x/xerrors"
)

type GetVariablesRequest struct {
	ParentType types.ConfigType
	ParentRef  string

	Tree             bool
	RemoveOverridden bool
}

func (h *ActionHandler) GetVariables(ctx context.Context, req *GetVariablesRequest) ([]*csapi.Variable, []*csapi.Secret, error) {
	var csvars []*csapi.Variable
	var cssecrets []*csapi.Secret

	switch req.ParentType {
	case types.ConfigTypeProjectGroup:
		var err error
		var resp *http.Response
		csvars, resp, err = h.configstoreClient.GetProjectGroupVariables(ctx, req.ParentRef, req.Tree)
		if err != nil {
			return nil, nil, ErrFromRemote(resp, err)
		}
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, ErrFromRemote(resp, err)
		}
	case types.ConfigTypeProject:
		var err error
		var resp *http.Response
		csvars, resp, err = h.configstoreClient.GetProjectVariables(ctx, req.ParentRef, req.Tree)
		if err != nil {
			return nil, nil, ErrFromRemote(resp, err)
		}
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, ErrFromRemote(resp, err)
		}
	}

	if req.RemoveOverridden {
		// remove overriden variables
		csvars = common.FilterOverriddenVariables(csvars)
	}

	return csvars, cssecrets, nil
}

type CreateVariableRequest struct {
	Name string

	ParentType types.ConfigType
	ParentRef  string

	Values []types.VariableValue
}

func (h *ActionHandler) CreateVariable(ctx context.Context, req *CreateVariableRequest) (*csapi.Variable, []*csapi.Secret, error) {
	isVariableOwner, err := h.IsVariableOwner(ctx, req.ParentType, req.ParentRef)
	if err != nil {
		return nil, nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return nil, nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, nil, util.NewErrBadRequest(errors.Errorf("invalid variable name %q", req.Name))
	}

	if len(req.Values) == 0 {
		return nil, nil, util.NewErrBadRequest(errors.Errorf("empty variable values"))
	}

	v := &types.Variable{
		Name: req.Name,
		Parent: types.Parent{
			Type: req.ParentType,
			ID:   req.ParentRef,
		},
		Values: req.Values,
	}

	var cssecrets []*csapi.Secret
	var rv *csapi.Variable

	switch req.ParentType {
	case types.ConfigTypeProjectGroup:
		var err error
		var resp *http.Response
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, errors.Errorf("failed to get project group %q secrets: %w", req.ParentRef, ErrFromRemote(resp, err))
		}

		h.log.Infof("creating project group variable")
		rv, resp, err = h.configstoreClient.CreateProjectGroupVariable(ctx, req.ParentRef, v)
		if err != nil {
			return nil, nil, errors.Errorf("failed to create variable: %w", ErrFromRemote(resp, err))
		}
	case types.ConfigTypeProject:
		var err error
		var resp *http.Response
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, errors.Errorf("failed to get project %q secrets: %w", req.ParentRef, ErrFromRemote(resp, err))
		}

		h.log.Infof("creating project variable")
		rv, resp, err = h.configstoreClient.CreateProjectVariable(ctx, req.ParentRef, v)
		if err != nil {
			return nil, nil, errors.Errorf("failed to create variable: %w", ErrFromRemote(resp, err))
		}
	}
	h.log.Infof("variable %s created, ID: %s", rv.Name, rv.ID)

	return rv, cssecrets, nil
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentType types.ConfigType, parentRef, name string) error {
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
		h.log.Infof("deleting project group variable")
		resp, err = h.configstoreClient.DeleteProjectGroupVariable(ctx, parentRef, name)
	case types.ConfigTypeProject:
		h.log.Infof("deleting project variable")
		resp, err = h.configstoreClient.DeleteProjectVariable(ctx, parentRef, name)
	}
	if err != nil {
		return errors.Errorf("failed to delete variable: %w", ErrFromRemote(resp, err))
	}
	return nil
}
