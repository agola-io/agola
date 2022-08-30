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
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func createVariableResponse(v *csapitypes.Variable, secrets []*csapitypes.Secret) *gwapitypes.VariableResponse {
	nv := &gwapitypes.VariableResponse{
		ID:         v.ID,
		Name:       v.Name,
		Values:     make([]gwapitypes.VariableValue, len(v.Values)),
		ParentPath: v.ParentPath,
	}

	for i, varvalue := range v.Values {
		nv.Values[i] = gwapitypes.VariableValue{
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
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewVariableHandler(log zerolog.Logger, ah *action.ActionHandler) *VariableHandler {
	return &VariableHandler{log: log, ah: ah}
}

func (h *VariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]
	_, removeoverridden := query["removeoverridden"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	areq := &action.GetVariablesRequest{
		ParentType:       parentType,
		ParentRef:        parentRef,
		Tree:             tree,
		RemoveOverridden: removeoverridden,
	}
	csvars, cssecrets, err := h.ah.GetVariables(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	variables := make([]*gwapitypes.VariableResponse, len(csvars))
	for i, v := range csvars {
		variables[i] = createVariableResponse(v, cssecrets)
	}

	if err := util.HTTPResponse(w, http.StatusOK, variables); err != nil {
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

	var req gwapitypes.CreateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}
	areq := &action.CreateVariableRequest{
		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     fromApiVariableValues(req.Values),
	}
	csvar, cssecrets, err := h.ah.CreateVariable(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createVariableResponse(csvar, cssecrets)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
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

	var req gwapitypes.UpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.UpdateVariableRequest{
		VariableName: variableName,

		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     fromApiVariableValues(req.Values),
	}
	csvar, cssecrets, err := h.ah.UpdateVariable(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createVariableResponse(csvar, cssecrets)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
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
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func fromApiVariableValues(apivalues []gwapitypes.VariableValueRequest) []cstypes.VariableValue {
	values := make([]cstypes.VariableValue, len(apivalues))
	for i, v := range apivalues {
		values[i] = cstypes.VariableValue{
			SecretName: v.SecretName,
			SecretVar:  v.SecretVar,
			When:       v.When,
		}
	}
	return values
}
