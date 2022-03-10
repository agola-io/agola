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
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type VariablesHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewVariablesHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *VariablesHandler {
	return &VariablesHandler{log: log, ah: ah, readDB: readDB}
}

func (h *VariablesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	variables, err := h.ah.GetVariables(ctx, parentType, parentRef, tree)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
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
				return errors.WithStack(err)
			}
			v.ParentPath = pp
		}
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resVariables); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateVariableHandler {
	return &CreateVariableHandler{log: log, ah: ah}
}

func (h *CreateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var req *csapitypes.CreateUpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateVariableRequest{
		Name: req.Name,
		Parent: types.Parent{
			Type: parentType,
			ID:   parentRef,
		},
		Values: req.Values,
	}

	variable, err := h.ah.CreateVariable(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, variable); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateVariableHandler {
	return &UpdateVariableHandler{log: log, ah: ah}
}

func (h *UpdateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var req *csapitypes.CreateUpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateVariableRequest{
		Name: req.Name,
		Parent: types.Parent{
			Type: parentType,
			ID:   parentRef,
		},
		Values: req.Values,
	}

	variable, err := h.ah.UpdateVariable(ctx, variableName, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, variable); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteVariableHandler {
	return &DeleteVariableHandler{log: log, ah: ah}
}

func (h *DeleteVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	err = h.ah.DeleteVariable(ctx, parentType, parentRef, variableName)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
