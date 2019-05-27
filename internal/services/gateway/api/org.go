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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type CreateOrgRequest struct {
	Name string `json:"name"`
}

type CreateOrgHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewCreateOrgHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	creq := &command.CreateOrgRequest{
		Name: req.Name,
	}

	org, err := h.ch.CreateOrg(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createOrgResponse(org)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteOrgHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteOrgHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteOrgHandler {
	return &DeleteOrgHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgName := vars["orgname"]

	resp, err := h.configstoreClient.DeleteOrg(ctx, orgName)
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

type OrgHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewOrgHandler(logger *zap.Logger, configstoreClient *csapi.Client) *OrgHandler {
	return &OrgHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgID := vars["orgid"]

	org, resp, err := h.configstoreClient.GetOrg(ctx, orgID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createOrgResponse(org)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type OrgByNameHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewOrgByNameHandler(logger *zap.Logger, configstoreClient *csapi.Client) *OrgByNameHandler {
	return &OrgByNameHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *OrgByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgName := vars["orgname"]

	org, resp, err := h.configstoreClient.GetOrgByName(ctx, orgName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createOrgResponse(org)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type OrgResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func createOrgResponse(o *types.Organization) *OrgResponse {
	org := &OrgResponse{
		ID:   o.ID,
		Name: o.Name,
	}
	return org
}

type OrgsHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewOrgsHandler(logger *zap.Logger, configstoreClient *csapi.Client) *OrgsHandler {
	return &OrgsHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *OrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	csorgs, resp, err := h.configstoreClient.GetOrgs(ctx, start, limit, asc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	orgs := make([]*OrgResponse, len(csorgs))
	for i, p := range csorgs {
		orgs[i] = createOrgResponse(p)
	}
	if err := httpResponse(w, http.StatusOK, orgs); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
