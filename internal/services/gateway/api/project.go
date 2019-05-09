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

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectRequest struct {
	Name                string           `json:"name,omitempty"`
	ParentRef           string           `json:"parent_ref,omitempty"`
	Visibility          types.Visibility `json:"visibility,omitempty"`
	RepoPath            string           `json:"repo_path,omitempty"`
	RemoteSourceName    string           `json:"remote_source_name,omitempty"`
	SkipSSHHostKeyCheck bool             `json:"skip_ssh_host_key_check,omitempty"`
}

type CreateProjectHandler struct {
	log        *zap.SugaredLogger
	ah         *action.ActionHandler
	exposedURL string
}

func NewCreateProjectHandler(logger *zap.Logger, ah *action.ActionHandler, exposedURL string) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ah: ah, exposedURL: exposedURL}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	areq := &action.CreateProjectRequest{
		Name:                req.Name,
		ParentRef:           req.ParentRef,
		Visibility:          req.Visibility,
		RepoPath:            req.RepoPath,
		RemoteSourceName:    req.RemoteSourceName,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
	}

	project, err := h.ah.CreateProject(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectResponse(project)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectReconfigHandler struct {
	log        *zap.SugaredLogger
	ah         *action.ActionHandler
	exposedURL string
}

func NewProjectReconfigHandler(logger *zap.Logger, ah *action.ActionHandler, exposedURL string) *ProjectReconfigHandler {
	return &ProjectReconfigHandler{log: logger.Sugar(), ah: ah, exposedURL: exposedURL}
}

func (h *ProjectReconfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	if err := h.ah.ReconfigProject(ctx, projectRef); err != nil {
		httpError(w, err)
		return
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectUpdateRepoLinkedAccountHandler struct {
	log        *zap.SugaredLogger
	ah         *action.ActionHandler
	exposedURL string
}

func NewProjectUpdateRepoLinkedAccountHandler(logger *zap.Logger, ah *action.ActionHandler, exposedURL string) *ProjectUpdateRepoLinkedAccountHandler {
	return &ProjectUpdateRepoLinkedAccountHandler{log: logger.Sugar(), ah: ah, exposedURL: exposedURL}
}

func (h *ProjectUpdateRepoLinkedAccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, err := h.ah.ProjectUpdateRepoLinkedAccount(ctx, projectRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectResponse(project)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteProjectHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteProjectHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	err = h.ah.DeleteProject(ctx, projectRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectHandler {
	return &ProjectHandler{log: logger.Sugar(), ah: ah}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, err := h.ah.GetProject(ctx, projectRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectResponse(project)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectResponse struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Path             string `json:"path,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	GlobalVisibility string `json:"global_visibility,omitempty"`
}

func createProjectResponse(r *csapi.Project) *ProjectResponse {
	res := &ProjectResponse{
		ID:               r.ID,
		Name:             r.Name,
		Path:             r.Path,
		ParentPath:       r.ParentPath,
		GlobalVisibility: string(r.GlobalVisibility),
	}

	return res
}
