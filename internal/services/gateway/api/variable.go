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

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
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

func (h *VariablesHandler) do(r *http.Request) ([]*gwapitypes.VariableResponse, error) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]
	_, removeoverridden := query["removeoverridden"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	areq := &action.GetVariablesRequest{
		ParentType:       parentType,
		ParentRef:        parentRef,
		Tree:             tree,
		RemoveOverridden: removeoverridden,
	}
	csvars, cssecrets, err := h.ah.GetVariables(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	variables := make([]*gwapitypes.VariableResponse, len(csvars))
	for i, v := range csvars {
		variables[i] = createVariableResponse(v, cssecrets)
	}

	return variables, nil
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

func (h *CreateVariableHandler) do(r *http.Request) (*gwapitypes.VariableResponse, error) {
	ctx := r.Context()
	parentType, parentRef, err := GetConfigTypeRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var req gwapitypes.CreateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}
	areq := &action.CreateVariableRequest{
		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     fromAPIVariableValues(req.Values),
	}
	csvar, cssecrets, err := h.ah.CreateVariable(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createVariableResponse(csvar, cssecrets)

	return res, nil
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

func (h *UpdateVariableHandler) do(r *http.Request) (*gwapitypes.VariableResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	variableName := vars["variablename"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var req gwapitypes.UpdateVariableRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.UpdateVariableRequest{
		VariableName: variableName,

		Name:       req.Name,
		ParentType: parentType,
		ParentRef:  parentRef,
		Values:     fromAPIVariableValues(req.Values),
	}
	csvar, cssecrets, err := h.ah.UpdateVariable(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createVariableResponse(csvar, cssecrets)

	return res, nil
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

	parentType, parentRef, err := GetConfigTypeRef(r)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.ah.DeleteVariable(ctx, parentType, parentRef, variableName)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func fromAPIVariableValues(apivalues []gwapitypes.VariableValueRequest) []cstypes.VariableValue {
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
