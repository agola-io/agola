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

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type VariablesHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewVariablesHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *VariablesHandler {
	return &VariablesHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *VariablesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	variables, err := h.ah.GetVariables(ctx, parentType, parentRef, tree)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resVariables := make([]*csapitypes.Variable, len(variables))
	for i, v := range variables {
		resVariables[i] = &csapitypes.Variable{Variable: v}
	}
	err = h.readDB.Do(ctx, func(tx *db.Tx) error {
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateVariableHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateVariableHandler {
	return &CreateVariableHandler{log: logger.Sugar(), ah: ah}
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

	variable, err = h.ah.CreateVariable(ctx, variable)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, variable); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateVariableHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateVariableHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateVariableHandler {
	return &UpdateVariableHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

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

	areq := &action.UpdateVariableRequest{
		VariableName: variableName,
		Variable:     variable,
	}
	variable, err = h.ah.UpdateVariable(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, variable); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteVariableHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteVariableHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteVariableHandler {
	return &DeleteVariableHandler{log: logger.Sugar(), ah: ah}
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

	err = h.ah.DeleteVariable(ctx, parentType, parentRef, variableName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
