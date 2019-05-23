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
