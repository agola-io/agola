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

	"github.com/pkg/errors"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/util"

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

	creq := &command.CreateProjectRequest{
		Name:                req.Name,
		ParentID:            req.ParentID,
		RepoPath:            req.RepoPath,
		RemoteSourceName:    req.RemoteSourceName,
		CurrentUserID:       userID,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
	}

	project, err := h.ch.CreateProject(ctx, creq)
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
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	if err := h.ch.ReconfigProject(ctx, projectRef); err != nil {
		httpError(w, err)
		return
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
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
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resp, err = h.configstoreClient.DeleteProject(ctx, project.ID)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
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
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createProjectResponse(project)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectResponse struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Path       string `json:"path,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
}

func createProjectResponse(r *csapi.Project) *ProjectResponse {
	res := &ProjectResponse{
		ID:         r.ID,
		Name:       r.Name,
		Path:       r.Path,
		ParentPath: r.ParentPath,
	}

	return res
}
