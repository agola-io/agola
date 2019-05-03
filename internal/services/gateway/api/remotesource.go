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
	"strconv"

	"github.com/pkg/errors"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateRemoteSourceHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.CreateRemoteSourceRequest{
		Name:               req.Name,
		APIURL:             req.APIURL,
		Type:               req.Type,
		AuthType:           req.AuthType,
		Oauth2ClientID:     req.Oauth2ClientID,
		Oauth2ClientSecret: req.Oauth2ClientSecret,
	}
	rs, err := h.ah.CreateRemoteSource(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
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
	rsRef := vars["remotesourceref"]

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, rsRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
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
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	remoteSources := make([]*RemoteSourceResponse, len(csRemoteSources))
	for i, rs := range csRemoteSources {
		remoteSources[i] = createRemoteSourceResponse(rs)
	}

	if err := httpResponse(w, http.StatusOK, remoteSources); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
