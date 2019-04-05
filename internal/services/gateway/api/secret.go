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

	if err := json.NewEncoder(w).Encode(secrets); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
