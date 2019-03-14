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
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type CreateRemoteSourceRequest struct {
	Name               string `json:"name"`
	APIURL             string `json:"apiurl"`
	Type               string `json:"type"`
	AuthType           string `json:"auth_type"`
	Oauth2ClientID     string `json:"oauth_2_client_id"`
	Oauth2ClientSecret string `json:"oauth_2_client_secret"`
}

type CreateRemoteSourceHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateRemoteSourceHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.createRemoteSource(ctx, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *CreateRemoteSourceHandler) createRemoteSource(ctx context.Context, req *CreateRemoteSourceRequest) (*types.RemoteSource, error) {
	if !util.ValidateName(req.Name) {
		return nil, errors.Errorf("invalid remotesource name %q", req.Name)
	}

	if req.Name == "" {
		return nil, errors.Errorf("remotesource name required")
	}
	if req.APIURL == "" {
		return nil, errors.Errorf("remotesource api url required")
	}
	if req.Type == "" {
		return nil, errors.Errorf("remotesource type required")
	}
	if req.AuthType == "" {
		return nil, errors.Errorf("remotesource auth type required")
	}

	// validate if the remote source type supports the required auth type
	if !common.SourceSupportsAuthType(types.RemoteSourceType(req.Type), types.RemoteSourceAuthType(req.AuthType)) {
		return nil, errors.Errorf("remotesource type %q doesn't support auth type %q", req.Type, req.AuthType)
	}

	if req.AuthType == string(types.RemoteSourceAuthTypeOauth2) {
		if req.Oauth2ClientID == "" {
			return nil, errors.Errorf("remotesource oauth2 clientid required")
		}
		if req.Oauth2ClientSecret == "" {
			return nil, errors.Errorf("remotesource oauth2 client secret required")
		}
	}

	rs := &types.RemoteSource{
		Name:               req.Name,
		Type:               types.RemoteSourceType(req.Type),
		AuthType:           types.RemoteSourceAuthType(req.AuthType),
		APIURL:             req.APIURL,
		Oauth2ClientID:     req.Oauth2ClientID,
		Oauth2ClientSecret: req.Oauth2ClientSecret,
	}

	h.log.Infof("creating remotesource")
	rs, _, err := h.configstoreClient.CreateRemoteSource(ctx, rs)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create remotesource")
	}
	h.log.Infof("remotesource %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

type RemoteSourceResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	AuthType string `json:"auth_type"`
}

func createRemoteSourceResponse(r *types.RemoteSource) *RemoteSourceResponse {
	rs := &RemoteSourceResponse{
		ID:       r.ID,
		Name:     r.Name,
		AuthType: string(r.AuthType),
	}
	return rs
}

type RemoteSourceHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewRemoteSourceHandler(logger *zap.Logger, configstoreClient *csapi.Client) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsID := vars["id"]

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, rsID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RemoteSourcesHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewRemoteSourcesHandler(logger *zap.Logger, configstoreClient *csapi.Client) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *RemoteSourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultRunsLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}
	if limit < 0 {
		http.Error(w, "limit must be greater or equal than 0", http.StatusBadRequest)
		return
	}
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	csRemoteSources, resp, err := h.configstoreClient.GetRemoteSources(ctx, start, limit, asc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	remoteSources := make([]*RemoteSourceResponse, len(csRemoteSources))
	for i, rs := range csRemoteSources {
		remoteSources[i] = createRemoteSourceResponse(rs)
	}

	if err := json.NewEncoder(w).Encode(remoteSources); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
