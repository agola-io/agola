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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// Variable augments types.Variable with dynamic data
type Variable struct {
	*types.Variable

	// dynamic data
	ParentPath string
}

type VariablesHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewVariablesHandler(logger *zap.Logger, readDB *readdb.ReadDB) *VariablesHandler {
	return &VariablesHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *VariablesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	_, tree := query["tree"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var variables []*types.Variable
	err = h.readDB.Do(func(tx *db.Tx) error {
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	resVariables := make([]*Variable, len(variables))
	for i, v := range variables {
		resVariables[i] = &Variable{Variable: v}
	}
	err = h.readDB.Do(func(tx *db.Tx) error {
		// populate parent path
		for _, v := range resVariables {
			pp, err := h.readDB.GetParentPath(tx, v.Parent.Type, v.Parent.ID)
			if err != nil {
				return err
			}
			v.ParentPath = pp
		}
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resVariables); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateVariableHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateVariableHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateVariableHandler {
	return &CreateVariableHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var variable *types.Variable
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&variable); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	variable.Parent.Type = parentType
	variable.Parent.ID = parentRef

	variable, err = h.ch.CreateVariable(ctx, variable)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, variable); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteVariableHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewDeleteVariableHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteVariableHandler {
	return &DeleteVariableHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	err = h.ch.DeleteVariable(ctx, parentType, parentRef, variableName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
