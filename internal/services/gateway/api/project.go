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

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateProjectHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gwapitypes.CreateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	areq := &action.CreateProjectRequest{
		Name:                req.Name,
		ParentRef:           req.ParentRef,
		Visibility:          cstypes.Visibility(req.Visibility),
		RepoPath:            req.RepoPath,
		RemoteSourceName:    req.RemoteSourceName,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		PassVarsToForkedPR:  req.PassVarsToForkedPR,
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

type UpdateProjectHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateProjectHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateProjectHandler {
	return &UpdateProjectHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var req gwapitypes.UpdateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var visibility *cstypes.Visibility
	if req.Visibility != nil {
		v := cstypes.Visibility(*req.Visibility)
		visibility = &v
	}

	areq := &action.UpdateProjectRequest{
		Name:               req.Name,
		ParentRef:          req.ParentRef,
		Visibility:         visibility,
		PassVarsToForkedPR: req.PassVarsToForkedPR,
	}
	project, err := h.ah.UpdateProject(ctx, projectRef, areq)
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectReconfigHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectReconfigHandler {
	return &ProjectReconfigHandler{log: logger.Sugar(), ah: ah}
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectUpdateRepoLinkedAccountHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectUpdateRepoLinkedAccountHandler {
	return &ProjectUpdateRepoLinkedAccountHandler{log: logger.Sugar(), ah: ah}
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

func createProjectResponse(r *csapitypes.Project) *gwapitypes.ProjectResponse {
	res := &gwapitypes.ProjectResponse{
		ID:                 r.ID,
		Name:               r.Name,
		Path:               r.Path,
		ParentPath:         r.ParentPath,
		Visibility:         gwapitypes.Visibility(r.Visibility),
		GlobalVisibility:   string(r.GlobalVisibility),
		PassVarsToForkedPR: r.PassVarsToForkedPR,
	}

	return res
}

type ProjectCreateRunHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewProjectCreateRunHandler(logger *zap.Logger, ah *action.ActionHandler) *ProjectCreateRunHandler {
	return &ProjectCreateRunHandler{log: logger.Sugar(), ah: ah}
}

func (h *ProjectCreateRunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var req gwapitypes.ProjectCreateRunRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	err = h.ah.ProjectCreateRun(ctx, projectRef, req.Branch, req.Tag, req.Ref, req.CommitSHA)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
