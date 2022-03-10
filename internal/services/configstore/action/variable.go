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
	"encoding/json"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gofrs/uuid"
)

func (h *ActionHandler) GetVariables(ctx context.Context, parentType types.ConfigType, parentRef string, tree bool) ([]*types.Variable, error) {
	var variables []*types.Variable
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		parentID, err := h.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if tree {
			variables, err = h.readDB.GetVariablesTree(tx, parentType, parentID)
		} else {
			variables, err = h.readDB.GetVariables(tx, parentID)
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
	if req.Parent.Type == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable parent type required"))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable parent id required"))
	}
	if req.Parent.Type != types.ConfigTypeProject && req.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid variable parent type %q", req.Parent.Type))
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

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the variable name
	cgNames := []string{util.EncodeSha256Hex("variablename-" + req.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		parentID, err := h.ResolveConfigID(tx, req.Parent.Type, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check duplicate variable name
		s, err := h.readDB.GetVariableByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if s != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q already exists", req.Name, req.Parent.Type, req.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	variable := &types.Variable{}
	variable.ID = uuid.Must(uuid.NewV4()).String()
	variable.Name = req.Name
	variable.Parent = req.Parent
	variable.Values = req.Values

	variablej, err := json.Marshal(variable)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal variable")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
			Data:       variablej,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return variable, errors.WithStack(err)
}

func (h *ActionHandler) UpdateVariable(ctx context.Context, curVariableName string, req *CreateUpdateVariableRequest) (*types.Variable, error) {
	if err := h.ValidateVariableReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the variable name

	var variable *types.Variable
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		parentID, err := h.ResolveConfigID(tx, req.Parent.Type, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Parent.ID = parentID

		// check variable exists
		variable, err = h.readDB.GetVariableByName(tx, req.Parent.ID, curVariableName)
		if err != nil {
			return errors.WithStack(err)
		}
		if variable == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q doesn't exists", curVariableName, req.Parent.Type, req.Parent.ID))
		}

		if variable.Name != req.Name {
			// check duplicate variable name
			u, err := h.readDB.GetVariableByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if u != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q for %s with id %q already exists", req.Name, req.Parent.Type, req.Parent.ID))
			}
		}

		// update current variable
		variable.Name = req.Name
		variable.Parent = req.Parent
		variable.Values = req.Values

		cgNames := []string{
			util.EncodeSha256Hex("variablename-" + variable.ID),
			util.EncodeSha256Hex("variablename-" + variable.Name),
		}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	variablej, err := json.Marshal(variable)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal variable")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
			Data:       variablej,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return variable, errors.WithStack(err)
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentType types.ConfigType, parentRef, variableName string) error {
	var variable *types.Variable

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		parentID, err := h.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return errors.WithStack(err)
		}

		// check variable existance
		variable, err = h.readDB.GetVariableByName(tx, parentID, variableName)
		if err != nil {
			return errors.WithStack(err)
		}
		if variable == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("variable with name %q doesn't exist", variableName))
		}

		// changegroup is the variable id
		cgNames := []string{util.EncodeSha256Hex("variableid-" + variable.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return errors.WithStack(err)
}
