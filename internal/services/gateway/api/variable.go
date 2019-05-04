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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type VariableValue struct {
	SecretName               string `json:"secret_name"`
	SecretVar                string `json:"secret_var"`
	MatchingSecretParentPath string `json:"matching_secret_parent_path"`

	When *types.When `json:"when"`
}

type VariableResponse struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Values     []VariableValue `json:"values"`
	ParentPath string          `json:"parent_path"`
}

func createVariableResponse(v *csapi.Variable, secrets []*csapi.Secret) *VariableResponse {
	nv := &VariableResponse{
		ID:         v.ID,
		Name:       v.Name,
		Values:     make([]VariableValue, len(v.Values)),
		ParentPath: v.ParentPath,
	}

	for i, varvalue := range v.Values {
		nv.Values[i] = VariableValue{
			SecretName: varvalue.SecretName,
			SecretVar:  varvalue.SecretVar,
			When:       varvalue.When,
		}
		// get matching secret for var value
		secret := common.GetVarValueMatchingSecret(varvalue, v.ParentPath, secrets)
		if secret != nil {
			nv.Values[i].MatchingSecretParentPath = secret.ParentPath
		}
	}

	return nv
}

type VariableHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewVariableHandler(logger *zap.Logger, ah *action.ActionHandler) *VariableHandler {
	return &VariableHandler{log: logger.Sugar(), ah: ah}
}

func (h *VariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]
	_, removeoverridden := query["removeoverridden"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	areq := &action.GetVariablesRequest{
		ParentType:       parentType,
		ParentRef:        parentRef,
		Tree:             tree,
		RemoveOverridden: removeoverridden,
	}
	csvars, cssecrets, err := h.ah.GetVariables(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	variables := make([]*VariableResponse, len(csvars))
	for i, v := range csvars {
		variables[i] = createVariableResponse(v, cssecrets)
	}

	if err := httpResponse(w, http.StatusOK, variables); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateVariableRequest struct {
	Name string `json:"name,omitempty"`

	Values []types.VariableValue `json:"values,omitempty"`
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

	var req CreateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}
	areq := &action.CreateVariableRequest{
		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     req.Values,
	}
	csvar, cssecrets, err := h.ah.CreateVariable(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createVariableResponse(csvar, cssecrets)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
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
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
