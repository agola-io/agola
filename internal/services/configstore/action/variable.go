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

func (h *ActionHandler) GetVariables(ctx context.Context, parentKind types.ObjectKind, parentRef string, tree bool) ([]*types.Variable, error) {
	var variables []*types.Variable
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, parentKind, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if tree {
			variables, err = h.d.GetVariablesTree(tx, parentKind, parentID)
		} else {
			variables, err = h.d.GetVariables(tx, parentID)
		}
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return variables, nil
}

func (h *ActionHandler) ValidateVariableReq(ctx context.Context, req *CreateUpdateVariableRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable name required"))
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid variable name %q", req.Name))
	}
	if len(req.Values) == 0 {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable values required"))
	}
	if req.Parent.Kind == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable parent kind required"))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable parent id required"))
	}
	if req.Parent.Kind != types.ObjectKindProject && req.Parent.Kind != types.ObjectKindProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid variable parent kind %q", req.Parent.Kind))
	}

	return nil
}

type CreateUpdateVariableRequest struct {
	Name   string
	Parent types.Parent
	Values []types.VariableValue
}

func (h *ActionHandler) CreateVariable(ctx context.Context, req *CreateUpdateVariableRequest) (*types.Variable, error) {
	if err := h.ValidateVariableReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var variable *types.Variable
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, req.Parent.Kind, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check duplicate variable name
		s, err := h.d.GetVariableByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if s != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID))
		}

		variable = types.NewVariable()
		variable.Name = req.Name
		variable.Parent = req.Parent
		variable.Values = req.Values

		if err := h.d.InsertVariable(tx, variable); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return variable, errors.WithStack(err)
}

func (h *ActionHandler) UpdateVariable(ctx context.Context, curVariableName string, req *CreateUpdateVariableRequest) (*types.Variable, error) {
	if err := h.ValidateVariableReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var variable *types.Variable
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, req.Parent.Kind, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check variable exists
		variable, err = h.d.GetVariableByName(tx, req.Parent.ID, curVariableName)
		if err != nil {
			return errors.WithStack(err)
		}
		if variable == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q doesn't exists", curVariableName, req.Parent.Kind, req.Parent.ID))
		}

		if variable.Name != req.Name {
			// check duplicate variable name
			u, err := h.d.GetVariableByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if u != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q already exists", req.Name, req.Parent.Kind, req.Parent.ID))
			}
		}

		// update current variable
		variable.Name = req.Name
		variable.Parent = req.Parent
		variable.Values = req.Values

		if err := h.d.UpdateVariable(tx, variable); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return variable, errors.WithStack(err)
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentKind types.ObjectKind, parentRef, variableName string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentID, err := h.ResolveObjectID(tx, parentKind, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}

		// check variable existance
		variable, err := h.d.GetVariableByName(tx, parentID, variableName)
		if err != nil {
			return errors.WithStack(err)
		}
		if variable == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q doesn't exist", variableName))
		}

		if err := h.d.DeleteVariable(tx, variable.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
