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
	"net/url"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectGroupRequest struct {
	Name     string `json:"name,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

type CreateProjectGroupHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
	exposedURL        string
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client, exposedURL string) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient, exposedURL: exposedURL}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctxUserID := ctx.Value("userid")
	if ctxUserID == nil {
		http.Error(w, "no authenticated user", http.StatusBadRequest)
		return
	}
	userID := ctxUserID.(string)
	h.log.Infof("userID: %q", userID)

	creq := &command.CreateProjectGroupRequest{
		Name:          req.Name,
		ParentID:      req.ParentID,
		CurrentUserID: userID,
	}

	projectGroup, err := h.ch.CreateProjectGroup(ctx, creq)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroup); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectGroupHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectGroupHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupID, err := url.PathUnescape(vars["projectgroupid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.log.Infof("projectGroupID: %s", projectGroupID)

	projectGroup, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectGroupProjectsHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectGroupProjectsHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupID, err := url.PathUnescape(vars["projectgroupid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.log.Infof("projectGroupID: %s", projectGroupID)

	csprojects, resp, err := h.configstoreClient.GetProjectGroupProjects(ctx, projectGroupID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	projects := make([]*ProjectResponse, len(csprojects))
	for i, p := range csprojects {
		projects[i] = createProjectResponse(p)
	}

	if err := json.NewEncoder(w).Encode(projects); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectGroupSubgroupsHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectGroupSubgroupsHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupID, err := url.PathUnescape(vars["projectgroupid"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.log.Infof("projectGroupID: %s", projectGroupID)

	cssubgroups, resp, err := h.configstoreClient.GetProjectGroupSubgroups(ctx, projectGroupID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	subgroups := make([]*ProjectGroupResponse, len(cssubgroups))
	for i, g := range cssubgroups {
		subgroups[i] = createProjectGroupResponse(g)
	}

	if err := json.NewEncoder(w).Encode(subgroups); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectGroupResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func createProjectGroupResponse(r *types.ProjectGroup) *ProjectGroupResponse {
	run := &ProjectGroupResponse{
		ID:   r.ID,
		Name: r.Name,
	}

	return run
}
