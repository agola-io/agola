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
			pp, err := h.readDB.GetPath(tx, v.Parent.Type, v.Parent.ID)
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
