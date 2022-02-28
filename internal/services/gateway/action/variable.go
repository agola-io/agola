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

type GetVariablesRequest struct {
	ParentType cstypes.ConfigType
	ParentRef  string

	Tree             bool
	RemoveOverridden bool
}

func (h *ActionHandler) GetVariables(ctx context.Context, req *GetVariablesRequest) ([]*csapitypes.Variable, []*csapitypes.Secret, error) {
	var csvars []*csapitypes.Variable
	var cssecrets []*csapitypes.Secret

	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		var err error
		csvars, _, err = h.configstoreClient.GetProjectGroupVariables(ctx, req.ParentRef, req.Tree)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}
		cssecrets, _, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}
	case cstypes.ConfigTypeProject:
		var err error
		csvars, _, err = h.configstoreClient.GetProjectVariables(ctx, req.ParentRef, req.Tree)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}
		cssecrets, _, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), err)
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

	ParentType cstypes.ConfigType
	ParentRef  string

	Values []cstypes.VariableValue
}

func (h *ActionHandler) CreateVariable(ctx context.Context, req *CreateVariableRequest) (*csapitypes.Variable, []*csapitypes.Secret, error) {
	isVariableOwner, err := h.IsVariableOwner(ctx, req.ParentType, req.ParentRef)
	if err != nil {
		return nil, nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return nil, nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid variable name %q", req.Name))
	}

	if len(req.Values) == 0 {
		return nil, nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty variable values"))
	}

	v := &cstypes.Variable{
		Name: req.Name,
		Parent: cstypes.Parent{
			Type: req.ParentType,
			ID:   req.ParentRef,
		},
		Values: req.Values,
	}

	var cssecrets []*csapitypes.Secret
	var rv *csapitypes.Variable

	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		var err error
		cssecrets, _, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project group %q secrets: %w", req.ParentRef, err))
		}

		h.log.Info().Msgf("creating project group variable")
		rv, _, err = h.configstoreClient.CreateProjectGroupVariable(ctx, req.ParentRef, v)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create variable: %w", err))
		}
	case cstypes.ConfigTypeProject:
		var err error
		cssecrets, _, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q secrets: %w", req.ParentRef, err))
		}

		h.log.Info().Msgf("creating project variable")
		rv, _, err = h.configstoreClient.CreateProjectVariable(ctx, req.ParentRef, v)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create variable: %w", err))
		}
	}
	h.log.Info().Msgf("variable %s created, ID: %s", rv.Name, rv.ID)

	return rv, cssecrets, nil
}

type UpdateVariableRequest struct {
	VariableName string

	Name string

	ParentType cstypes.ConfigType
	ParentRef  string

	Values []cstypes.VariableValue
}

func (h *ActionHandler) UpdateVariable(ctx context.Context, req *UpdateVariableRequest) (*csapitypes.Variable, []*csapitypes.Secret, error) {
	isVariableOwner, err := h.IsVariableOwner(ctx, req.ParentType, req.ParentRef)
	if err != nil {
		return nil, nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return nil, nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid variable name %q", req.Name))
	}

	if len(req.Values) == 0 {
		return nil, nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty variable values"))
	}

	v := &cstypes.Variable{
		Name: req.Name,
		Parent: cstypes.Parent{
			Type: req.ParentType,
			ID:   req.ParentRef,
		},
		Values: req.Values,
	}

	var cssecrets []*csapitypes.Secret
	var rv *csapitypes.Variable

	switch req.ParentType {
	case cstypes.ConfigTypeProjectGroup:
		var err error
		cssecrets, _, err = h.configstoreClient.GetProjectGroupSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project group %q secrets: %w", req.ParentRef, err))
		}

		h.log.Info().Msgf("creating project group variable")
		rv, _, err = h.configstoreClient.UpdateProjectGroupVariable(ctx, req.ParentRef, req.VariableName, v)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create variable: %w", err))
		}
	case cstypes.ConfigTypeProject:
		var err error
		cssecrets, _, err = h.configstoreClient.GetProjectSecrets(ctx, req.ParentRef, true)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q secrets: %w", req.ParentRef, err))
		}

		h.log.Info().Msgf("creating project variable")
		rv, _, err = h.configstoreClient.UpdateProjectVariable(ctx, req.ParentRef, req.VariableName, v)
		if err != nil {
			return nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create variable: %w", err))
		}
	}
	h.log.Info().Msgf("variable %s created, ID: %s", rv.Name, rv.ID)

	return rv, cssecrets, nil
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentType cstypes.ConfigType, parentRef, name string) error {
	isVariableOwner, err := h.IsVariableOwner(ctx, parentType, parentRef)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isVariableOwner {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	switch parentType {
	case cstypes.ConfigTypeProjectGroup:
		h.log.Info().Msgf("deleting project group variable")
		_, err = h.configstoreClient.DeleteProjectGroupVariable(ctx, parentRef, name)
	case cstypes.ConfigTypeProject:
		h.log.Info().Msgf("deleting project variable")
		_, err = h.configstoreClient.DeleteProjectVariable(ctx, parentRef, name)
	}
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to delete variable: %w", err))
	}
	return nil
}
