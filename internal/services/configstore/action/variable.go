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
	"encoding/json"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func (h *ActionHandler) CreateVariable(ctx context.Context, variable *types.Variable) (*types.Variable, error) {
	if variable.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable name required"))
	}
	if !util.ValidateName(variable.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid variable name %q", variable.Name))
	}
	if len(variable.Values) == 0 {
		return nil, util.NewErrBadRequest(errors.Errorf("variable values required"))
	}
	if variable.Parent.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable parent type required"))
	}
	if variable.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable parent id required"))
	}
	if variable.Parent.Type != types.ConfigTypeProject && variable.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid variable parent type %q", variable.Parent.Type))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the variable name
	cgNames := []string{util.EncodeSha256Hex("variablename-" + variable.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
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
	return variable, err
}

func (h *ActionHandler) DeleteVariable(ctx context.Context, parentType types.ConfigType, parentRef, variableName string) error {
	var variable *types.Variable

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
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
