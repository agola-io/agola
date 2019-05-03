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
	"net/url"

	"github.com/pkg/errors"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectGroupRequest struct {
	Name       string           `json:"name,omitempty"`
	ParentID   string           `json:"parent_id,omitempty"`
	Visibility types.Visibility `json:"visibility,omitempty"`
}

type CreateProjectGroupHandler struct {
	log               *zap.SugaredLogger
	ah                *action.ActionHandler
	configstoreClient *csapi.Client
	exposedURL        string
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler, configstoreClient *csapi.Client, exposedURL string) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ah: ah, configstoreClient: configstoreClient, exposedURL: exposedURL}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	userIDVal := ctx.Value("userid")
	if userIDVal == nil {
		httpError(w, util.NewErrBadRequest(errors.Errorf("user not authenticated")))
		return
	}
	userID := userIDVal.(string)
	h.log.Infof("userID: %q", userID)

	creq := &action.CreateProjectGroupRequest{
		Name:          req.Name,
		ParentID:      req.ParentID,
		Visibility:    req.Visibility,
		CurrentUserID: userID,
	}

	projectGroup, err := h.ah.CreateProjectGroup(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
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
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	projectGroup, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
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
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	csprojects, resp, err := h.configstoreClient.GetProjectGroupProjects(ctx, projectGroupRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	projects := make([]*ProjectResponse, len(csprojects))
	for i, p := range csprojects {
		projects[i] = createProjectResponse(p)
	}

	if err := httpResponse(w, http.StatusOK, projects); err != nil {
		h.log.Errorf("err: %+v", err)
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
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	cssubgroups, resp, err := h.configstoreClient.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	subgroups := make([]*ProjectGroupResponse, len(cssubgroups))
	for i, g := range cssubgroups {
		subgroups[i] = createProjectGroupResponse(g)
	}

	if err := httpResponse(w, http.StatusOK, subgroups); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectGroupResponse struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Path             string `json:"path,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	GlobalVisibility string `json:"global_visibility,omitempty"`
}

func createProjectGroupResponse(r *csapi.ProjectGroup) *ProjectGroupResponse {
	run := &ProjectGroupResponse{
		ID:               r.ID,
		Name:             r.Name,
		Path:             r.Path,
		ParentPath:       r.ParentPath,
		GlobalVisibility: string(r.GlobalVisibility),
	}

	return run
}
