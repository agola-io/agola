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
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetVariables(ctx context.Context, parentType types.ConfigType, parentRef string, tree bool) ([]*types.Variable, error) {
	var variables []*types.Variable
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		parentID, err := h.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}
		if tree {
			variables, err = h.readDB.GetVariablesTree(tx, parentType, parentID)
		} else {
			variables, err = h.readDB.GetVariables(tx, parentID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	return variables, nil
}

func (h *ActionHandler) ValidateVariable(ctx context.Context, variable *types.Variable) error {
	if variable.Name == "" {
		return util.NewErrBadRequest(errors.Errorf("variable name required"))
	}
	if !util.ValidateName(variable.Name) {
		return util.NewErrBadRequest(errors.Errorf("invalid variable name %q", variable.Name))
	}
	if len(variable.Values) == 0 {
		return util.NewErrBadRequest(errors.Errorf("variable values required"))
	}
	if variable.Parent.Type == "" {
		return util.NewErrBadRequest(errors.Errorf("variable parent type required"))
	}
	if variable.Parent.ID == "" {
		return util.NewErrBadRequest(errors.Errorf("variable parent id required"))
	}
	if variable.Parent.Type != types.ConfigTypeProject && variable.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewErrBadRequest(errors.Errorf("invalid variable parent type %q", variable.Parent.Type))
	}

	return nil
}

func (h *ActionHandler) CreateVariable(ctx context.Context, variable *types.Variable) (*types.Variable, error) {
	if err := h.ValidateVariable(ctx, variable); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the variable name
	cgNames := []string{util.EncodeSha256Hex("variablename-" + variable.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		parentID, err := h.readDB.ResolveConfigID(tx, variable.Parent.Type, variable.Parent.ID)
		if err != nil {
			return err
		}
		variable.Parent.ID = parentID

		// check duplicate variable name
		s, err := h.readDB.GetVariableByName(tx, variable.Parent.ID, variable.Name)
		if err != nil {
			return err
		}
		if s != nil {
			return util.NewErrBadRequest(errors.Errorf("variable with name %q for %s with id %q already exists", variable.Name, variable.Parent.Type, variable.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	variable.ID = uuid.NewV4().String()

	variablej, err := json.Marshal(variable)
	if err != nil {
		return nil, errors.Errorf("failed to marshal variable: %w", err)
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
	return variable, err
}

type UpdateVariableRequest struct {
	VariableName string

	Variable *types.Variable
}

func (h *ActionHandler) UpdateVariable(ctx context.Context, req *UpdateVariableRequest) (*types.Variable, error) {
	if err := h.ValidateVariable(ctx, req.Variable); err != nil {
		return nil, err
	}

	var curVariable *types.Variable
	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the variable name

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		parentID, err := h.readDB.ResolveConfigID(tx, req.Variable.Parent.Type, req.Variable.Parent.ID)
		if err != nil {
			return err
		}
		req.Variable.Parent.ID = parentID

		// check variable exists
		curVariable, err = h.readDB.GetVariableByName(tx, req.Variable.Parent.ID, req.VariableName)
		if err != nil {
			return err
		}
		if curVariable == nil {
			return util.NewErrBadRequest(errors.Errorf("variable with name %q for %s with id %q doesn't exists", req.VariableName, req.Variable.Parent.Type, req.Variable.Parent.ID))
		}

		if curVariable.Name != req.Variable.Name {
			// check duplicate variable name
			u, err := h.readDB.GetVariableByName(tx, req.Variable.Parent.ID, req.Variable.Name)
			if err != nil {
				return err
			}
			if u != nil {
				return util.NewErrBadRequest(errors.Errorf("variable with name %q for %s with id %q already exists", req.Variable.Name, req.Variable.Parent.Type, req.Variable.Parent.ID))
			}
		}

		// set/override ID that must be kept from the current variable
		req.Variable.ID = curVariable.ID

		cgNames := []string{
			util.EncodeSha256Hex("variablename-" + req.Variable.ID),
			util.EncodeSha256Hex("variablename-" + req.Variable.Name),
		}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	variablej, err := json.Marshal(req.Variable)
	if err != nil {
		return nil, errors.Errorf("failed to marshal variable: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeVariable),
			ID:         req.Variable.ID,
			Data:       variablej,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return req.Variable, err
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentType types.ConfigType, parentRef, variableName string) error {
	var variable *types.Variable

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		parentID, err := h.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}

		// check variable existance
		variable, err = h.readDB.GetVariableByName(tx, parentID, variableName)
		if err != nil {
			return err
		}
		if variable == nil {
			return util.NewErrBadRequest(errors.Errorf("variable with name %q doesn't exist", variableName))
		}

		// changegroup is the variable id
		cgNames := []string{util.EncodeSha256Hex("variableid-" + variable.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
