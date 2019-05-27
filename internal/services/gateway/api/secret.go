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
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type SecretResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ParentPath string `json:"parent_path"`
}

func createSecretResponse(s *types.Secret) *SecretResponse {
	return &SecretResponse{
		ID:         s.ID,
		Name:       s.Name,
		ParentPath: s.Parent.Path,
	}
}

type SecretHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewSecretHandler(logger *zap.Logger, configstoreClient *csapi.Client) *SecretHandler {
	return &SecretHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *SecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var cssecrets []*types.Secret
	switch parentType {
	case types.ConfigTypeProjectGroup:
		cssecrets, _, err = h.configstoreClient.GetProjectGroupSecrets(ctx, parentRef, tree)
	case types.ConfigTypeProject:
		cssecrets, _, err = h.configstoreClient.GetProjectSecrets(ctx, parentRef, tree)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secrets := make([]*SecretResponse, len(cssecrets))
	for i, s := range cssecrets {
		secrets[i] = createSecretResponse(s)
	}

	if err := httpResponse(w, http.StatusOK, secrets); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateSecretRequest struct {
	Name string `json:"name,omitempty"`

	Type types.SecretType `json:"type,omitempty"`

	// internal secret
	Data map[string]string `json:"data,omitempty"`

	// external secret
	SecretProviderID string `json:"secret_provider_id,omitempty"`
	Path             string `json:"path,omitempty"`
}

type CreateSecretHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateSecretHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateSecretHandler {
	return &CreateSecretHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CreateSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		return
	}

	var req CreateSecretRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !util.ValidateName(req.Name) {
		err := errors.Errorf("invalid secret name %q", req.Name)
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	s := &types.Secret{
		Name: req.Name,
		Type: req.Type,
		Data: req.Data,
	}

	switch parentType {
	case types.ConfigTypeProjectGroup:
		h.log.Infof("creating project group secret")
		s, _, err = h.configstoreClient.CreateProjectGroupSecret(ctx, parentRef, s)
	case types.ConfigTypeProject:
		h.log.Infof("creating project secret")
		s, _, err = h.configstoreClient.CreateProjectSecret(ctx, parentRef, s)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.log.Infof("secret %s created, ID: %s", s.Name, s.ID)

	res := createSecretResponse(s)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteSecretHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteSecretHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteSecretHandler {
	return &DeleteSecretHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretName := vars["secretname"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		return
	}

	var resp *http.Response
	switch parentType {
	case types.ConfigTypeProjectGroup:
		h.log.Infof("deleting project group secret")
		resp, err = h.configstoreClient.DeleteProjectGroupSecret(ctx, parentRef, secretName)
	case types.ConfigTypeProject:
		h.log.Infof("deleting project secret")
		resp, err = h.configstoreClient.DeleteProjectSecret(ctx, parentRef, secretName)
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
