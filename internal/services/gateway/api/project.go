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
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectRequest struct {
	Name                string `json:"name"`
	RepoURL             string `json:"repo_url"`
	RemoteSourceName    string `json:"remote_source_name"`
	SkipSSHHostKeyCheck bool   `json:"skip_ssh_host_key_check"`
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
	vars := mux.Vars(r)
	orgname := vars["orgname"]

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
		RepoURL:             req.RepoURL,
		RemoteSourceName:    req.RemoteSourceName,
		UserID:              userID,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
	}

	ownerID, code, userErr, err := getOwnerID(ctx, h.configstoreClient, "", orgname, true)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
		return
	}
	if orgname != "" {
		creq.OwnerType = types.OwnerTypeOrganization
		creq.OwnerID = ownerID
	}

	project, err := h.ch.CreateProject(ctx, creq)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	projectName := vars["projectname"]
	username := vars["username"]
	orgname := vars["orgname"]

	ownerID, code, userErr, err := getOwnerID(ctx, h.configstoreClient, username, orgname, false)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
		return
	}

	if err := h.ch.ReconfigProject(ctx, ownerID, projectName); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	projectName := vars["projectname"]
	username := vars["username"]
	orgname := vars["orgname"]

	ownerID, code, userErr, err := getOwnerID(ctx, h.configstoreClient, username, orgname, true)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
		return
	}

	project, resp, err := h.configstoreClient.GetProjectByName(ctx, ownerID, projectName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, fmt.Sprintf("project with name %q doesn't exist", projectName), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err = h.configstoreClient.DeleteProject(ctx, project.ID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	projectID := vars["projectid"]

	project, resp, err := h.configstoreClient.GetProject(ctx, projectID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createProjectResponse(project)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type ProjectByNameHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectByNameHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectByNameHandler {
	return &ProjectByNameHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectName := vars["projectname"]
	username := vars["username"]
	orgname := vars["orgname"]

	ownerID, code, userErr, err := getOwnerID(ctx, h.configstoreClient, username, orgname, false)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
		return
	}

	project, resp, err := h.configstoreClient.GetProjectByName(ctx, ownerID, projectName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createProjectResponse(project)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type GetProjectsResponse struct {
	Projects []*ProjectResponse `json:"projects"`
}

type ProjectResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func createProjectResponse(r *types.Project) *ProjectResponse {
	run := &ProjectResponse{
		ID:   r.ID,
		Name: r.Name,
	}

	return run
}

type ProjectsHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewProjectsHandler(logger *zap.Logger, configstoreClient *csapi.Client) *ProjectsHandler {
	return &ProjectsHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *ProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	username := vars["username"]
	orgname := vars["orgname"]

	ownerID, code, userErr, err := getOwnerID(ctx, h.configstoreClient, username, orgname, true)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
		return
	}

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

	csprojects, resp, err := h.configstoreClient.GetOwnerProjects(ctx, ownerID, start, limit, asc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	projects := make([]*ProjectResponse, len(csprojects))
	for i, p := range csprojects {
		projects[i] = createProjectResponse(p)
	}
	getProjectsResponse := &GetProjectsResponse{
		Projects: projects,
	}

	if err := json.NewEncoder(w).Encode(getProjectsResponse); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getOwnerID(ctx context.Context, configstoreClient *csapi.Client, username, orgname string, useAuthUser bool) (string, int, string, error) {
	var ownerID string
	switch {
	case username != "":
		user, resp, err := configstoreClient.GetUserByName(ctx, username)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				err = errors.Errorf("user %q doens't exist", username)
				return "", http.StatusNotFound, err.Error(), err
			}
			return "", http.StatusInternalServerError, "", err
		}
		ownerID = user.ID
	case orgname != "":
		org, resp, err := configstoreClient.GetOrgByName(ctx, orgname)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				err = errors.Errorf("organization %q doens't exist", orgname)
				return "", http.StatusNotFound, err.Error(), err
			}
			return "", http.StatusInternalServerError, "", err
		}
		ownerID = org.ID
	default:
		if useAuthUser {
			// use the current authenticated user
			ctxUserID := ctx.Value("userid")
			if ctxUserID == nil {
				err := errors.New("no authenticated user")
				return "", http.StatusBadRequest, err.Error(), err
			}
			ownerID = ctxUserID.(string)
		} else {
			err := errors.New("no user or org name specified")
			return "", http.StatusBadRequest, err.Error(), err
		}
	}

	return ownerID, 0, "", nil
}
