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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectGroupRequest struct {
	Name       string           `json:"name"`
	ParentRef  string           `json:"parent_ref"`
	Visibility types.Visibility `json:"visibility"`
}

type CreateProjectGroupHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ah: ah}
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
		ParentRef:     req.ParentRef,
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

type UpdateProjectGroupRequest struct {
	Name       string           `json:"name,omitempty"`
	Visibility types.Visibility `json:"visibility,omitempty"`
}

type UpdateProjectGroupHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateProjectGroupHandler {
	return &UpdateProjectGroupHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var req UpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	areq := &action.UpdateProjectGroupRequest{
		Name:       req.Name,
		Visibility: req.Visibility,
	}
	projectGroup, err := h.ah.UpdateProjectGroup(ctx, projectGroupRef, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteProjectGroupHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteProjectGroupHandler {
	return &DeleteProjectGroupHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	err = h.ah.DeleteProjectGroup(ctx, projectGroupRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectGroupHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: logger.Sugar(), ah: ah}
}

func (h *ProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	projectGroup, err := h.ah.GetProjectGroup(ctx, projectGroupRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectGroupProjectsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectGroupProjectsHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: logger.Sugar(), ah: ah}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	csprojects, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if httpError(w, err) {
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectGroupSubgroupsHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: logger.Sugar(), ah: ah}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	cssubgroups, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if httpError(w, err) {
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
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Path             string           `json:"path"`
	ParentPath       string           `json:"parent_path"`
	Visibility       types.Visibility `json:"visibility"`
	GlobalVisibility string           `json:"global_visibility"`
}

func createProjectGroupResponse(r *csapi.ProjectGroup) *ProjectGroupResponse {
	run := &ProjectGroupResponse{
		ID:               r.ID,
		Name:             r.Name,
		Path:             r.Path,
		ParentPath:       r.ParentPath,
		Visibility:       r.Visibility,
		GlobalVisibility: string(r.GlobalVisibility),
	}

	return run
}
