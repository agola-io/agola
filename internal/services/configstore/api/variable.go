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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type VariablesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewVariablesHandler(log zerolog.Logger, ah *action.ActionHandler) *VariablesHandler {
	return &VariablesHandler{log: log, ah: ah}
}

func (h *VariablesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *VariablesHandler) do(r *http.Request) ([]*csapitypes.Variable, error) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res, err := h.ah.GetVariables(ctx, parentKind, parentRef, tree)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resVariables := make([]*csapitypes.Variable, len(res.Variables))
	for i, v := range res.Variables {
		resVariables[i] = &csapitypes.Variable{Variable: v, ParentPath: res.ParentPaths[v.ID]}
	}

	return resVariables, nil
}

type CreateVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateVariableHandler {
	return &CreateVariableHandler{log: log, ah: ah}
}

func (h *CreateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateVariableHandler) do(r *http.Request) (*types.Variable, error) {
	ctx := r.Context()
	parentKind, parentRef, err := GetObjectKindRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var req *csapitypes.CreateUpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateVariableRequest{
		Name: req.Name,
		Parent: types.Parent{
			Kind: parentKind,
			ID:   parentRef,
		},
		Values: req.Values,
	}

	variable, err := h.ah.CreateVariable(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return variable, nil
}

type UpdateVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateVariableHandler {
	return &UpdateVariableHandler{log: log, ah: ah}
}

func (h *UpdateVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateVariableHandler) do(r *http.Request) (*types.Variable, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var req *csapitypes.CreateUpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateVariableRequest{
		Name: req.Name,
		Parent: types.Parent{
			Kind: parentKind,
			ID:   parentRef,
		},
		Values: req.Values,
	}

	variable, err := h.ah.UpdateVariable(ctx, variableName, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return variable, nil
}

type DeleteVariableHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteVariableHandler {
	return &DeleteVariableHandler{log: log, ah: ah}
}

func (h *DeleteVariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteVariableHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.ah.DeleteVariable(ctx, parentKind, parentRef, variableName)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
