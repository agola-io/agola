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
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
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

func createVariableResponse(v *types.Variable, secrets []*types.Secret) *VariableResponse {
	nv := &VariableResponse{
		ID:         v.ID,
		Name:       v.Name,
		Values:     make([]VariableValue, len(v.Values)),
		ParentPath: v.Parent.Path,
	}

	for i, varvalue := range v.Values {
		nv.Values[i] = VariableValue{
			SecretName: varvalue.SecretName,
			SecretVar:  varvalue.SecretVar,
			When:       varvalue.When,
		}
		// get matching secret for var value
		secret := common.GetVarValueMatchingSecret(varvalue, v.Parent.Path, secrets)
		if secret != nil {
			nv.Values[i].MatchingSecretParentPath = secret.Parent.Path
		}
	}

	return nv
}

type VariableHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewVariableHandler(logger *zap.Logger, configstoreClient *csapi.Client) *VariableHandler {
	return &VariableHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *VariableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]
	_, removeoverriden := query["removeoverriden"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var csvars []*types.Variable
	var cssecrets []*types.Secret

	switch parentType {
	case types.ConfigTypeProjectGroup:
		var err error
		var resp *http.Response
		csvars, resp, err = h.configstoreClient.GetProjectGroupVariables(ctx, parentRef, tree)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, parentRef, true)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
	case types.ConfigTypeProject:
		var err error
		var resp *http.Response
		csvars, resp, err = h.configstoreClient.GetProjectVariables(ctx, parentRef, tree)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, parentRef, true)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
	}

	if removeoverriden {
		// remove overriden variables
		csvars = common.FilterOverridenVariables(csvars)
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
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateVariableHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateVariableHandler {
	return &CreateVariableHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
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

	if !util.ValidateName(req.Name) {
		httpError(w, util.NewErrBadRequest(errors.Errorf("invalid secret name %q", req.Name)))
		return
	}

	if len(req.Values) == 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("empty variable values")))
		return
	}

	v := &types.Variable{
		Name: req.Name,
		Parent: types.Parent{
			Type: parentType,
			ID:   parentRef,
		},
		Values: req.Values,
	}

	var cssecrets []*types.Secret

	switch parentType {
	case types.ConfigTypeProjectGroup:
		var err error
		var resp *http.Response
		cssecrets, resp, err = h.configstoreClient.GetProjectGroupSecrets(ctx, parentRef, true)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}

		h.log.Infof("creating project group variable")
		v, resp, err = h.configstoreClient.CreateProjectGroupVariable(ctx, parentRef, v)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
	case types.ConfigTypeProject:
		var err error
		var resp *http.Response
		cssecrets, resp, err = h.configstoreClient.GetProjectSecrets(ctx, parentRef, true)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}

		h.log.Infof("creating project variable")
		v, resp, err = h.configstoreClient.CreateProjectVariable(ctx, parentRef, v)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
	}
	h.log.Infof("variable %s created, ID: %s", v.Name, v.ID)

	res := createVariableResponse(v, cssecrets)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteVariableHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteVariableHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteVariableHandler {
	return &DeleteVariableHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
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

	var resp *http.Response
	switch parentType {
	case types.ConfigTypeProjectGroup:
		h.log.Infof("deleting project group variable")
		resp, err = h.configstoreClient.DeleteProjectGroupVariable(ctx, parentRef, variableName)
	case types.ConfigTypeProject:
		h.log.Infof("deleting project variable")
		resp, err = h.configstoreClient.DeleteProjectVariable(ctx, parentRef, variableName)
	}
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
