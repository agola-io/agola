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
	"fmt"
	"net/http"
	"net/url"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectRequest struct {
	Name                string `json:"name,omitempty"`
	ParentID            string `json:"parent_id,omitempty"`
	RepoPath            string `json:"repo_path,omitempty"`
	RemoteSourceName    string `json:"remote_source_name,omitempty"`
	SkipSSHHostKeyCheck bool   `json:"skip_ssh_host_key_check,omitempty"`
}

type CreateProjectHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
	exposedURL        string
}

func NewCreateProjectHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client, exposedURL string) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient, exposedURL: exposedURL}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateProjectRequest
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

	creq := &command.CreateProjectRequest{
		Name:                req.Name,
		ParentID:            req.ParentID,
		RepoPath:            req.RepoPath,
		RemoteSourceName:    req.RemoteSourceName,
		CurrentUserID:       userID,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
	}

	project, err := h.ch.CreateProject(ctx, creq)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := createProjectResponse(project)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectReconfigHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
	exposedURL        string
}

func NewProjectReconfigHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client, exposedURL string) *ProjectReconfigHandler {
	return &ProjectReconfigHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient, exposedURL: exposedURL}
}

func (h *ProjectReconfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.ch.ReconfigProject(ctx, projectRef); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type DeleteProjectHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteProjectHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, fmt.Sprintf("project with ref %q doesn't exist", projectRef), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	resp, err = h.configstoreClient.DeleteProject(ctx, project.ID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectHandler {
	return &ProjectHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createProjectResponse(project)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type ProjectResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func createProjectResponse(r *types.Project) *ProjectResponse {
	res := &ProjectResponse{
		ID:   r.ID,
		Name: r.Name,
	}

	return res
}
