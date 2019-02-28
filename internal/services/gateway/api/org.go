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
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type CreateOrgRequest struct {
	Name string `json:"name"`
}

type CreateOrgHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateOrgHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateOrgHandler {
	return &CreateOrgHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	org, err := h.createOrg(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(org); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *CreateOrgHandler) createOrg(ctx context.Context, req *CreateOrgRequest) (*OrgResponse, error) {
	if !util.ValidateName(req.Name) {
		return nil, errors.Errorf("invalid org name %q", req.Name)
	}

	u := &types.Organization{
		Name: req.Name,
	}

	h.log.Infof("creating org")
	u, _, err := h.configstoreClient.CreateOrg(ctx, u)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create org")
	}
	h.log.Infof("org %s created, ID: %s", u.Name, u.ID)

	res := createOrgResponse(u)
	return res, nil
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CurrentOrgHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCurrentOrgHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CurrentOrgHandler {
	return &CurrentOrgHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CurrentOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orgIDVal := ctx.Value("orgid")
	if orgIDVal == nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	orgID := orgIDVal.(string)

	org, resp, err := h.configstoreClient.GetOrg(ctx, orgID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createOrgResponse(org)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createOrgResponse(org)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createOrgResponse(org)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type OrgsResponse struct {
	Orgs []*OrgResponse `json:"orgs"`
}

type OrgResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func createOrgResponse(r *types.Organization) *OrgResponse {
	org := &OrgResponse{
		ID:   r.ID,
		Name: r.Name,
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	orgs := make([]*OrgResponse, len(csorgs))
	for i, p := range csorgs {
		orgs[i] = createOrgResponse(p)
	}
	orgsResponse := &OrgsResponse{
		Orgs: orgs,
	}

	if err := json.NewEncoder(w).Encode(orgsResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
