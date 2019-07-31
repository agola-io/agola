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

	"agola.io/agola/internal/services/common"
	csapi "agola.io/agola/internal/services/configstore/api"
	cstypes "agola.io/agola/internal/services/configstore/types"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type VariableValue struct {
	SecretName               string `json:"secret_name"`
	SecretVar                string `json:"secret_var"`
	MatchingSecretParentPath string `json:"matching_secret_parent_path"`

	When *cstypes.When `json:"when"`
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

	Values []cstypes.VariableValue `json:"values,omitempty"`
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

type UpdateVariableRequest struct {
	Name string `json:"name,omitempty"`

	Values []cstypes.VariableValue `json:"values,omitempty"`
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

	var req UpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}
	areq := &action.UpdateVariableRequest{
		VariableName: variableName,

		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     req.Values,
	}
	csvar, cssecrets, err := h.ah.UpdateVariable(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createVariableResponse(csvar, cssecrets)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
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
