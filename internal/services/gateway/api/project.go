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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

type CreateProjectHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateProjectHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateProjectHandler {
	return &CreateProjectHandler{log: log, ah: ah}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateProjectHandler) do(r *http.Request) (*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()

	var req gwapitypes.CreateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateProjectRequest{
		Name:                        req.Name,
		ParentRef:                   req.ParentRef,
		Visibility:                  cstypes.Visibility(req.Visibility),
		RepoPath:                    req.RepoPath,
		RemoteSourceName:            req.RemoteSourceName,
		SkipSSHHostKeyCheck:         req.SkipSSHHostKeyCheck,
		PassVarsToForkedPR:          req.PassVarsToForkedPR,
		MembersCanPerformRunActions: req.MembersCanPerformRunActions,
	}

	project, err := h.ah.CreateProject(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectResponse(project)

	return res, nil
}

type UpdateProjectHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateProjectHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateProjectHandler {
	return &UpdateProjectHandler{log: log, ah: ah}
}

func (h *UpdateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateProjectHandler) do(r *http.Request) (*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var req gwapitypes.UpdateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var visibility *cstypes.Visibility
	if req.Visibility != nil {
		v := cstypes.Visibility(*req.Visibility)
		visibility = &v
	}

	areq := &action.UpdateProjectRequest{
		Name:                        req.Name,
		ParentRef:                   req.ParentRef,
		Visibility:                  visibility,
		PassVarsToForkedPR:          req.PassVarsToForkedPR,
		MembersCanPerformRunActions: req.MembersCanPerformRunActions,
	}
	project, err := h.ah.UpdateProject(ctx, projectRef, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectResponse(project)

	return res, nil
}

type ProjectReconfigHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectReconfigHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectReconfigHandler {
	return &ProjectReconfigHandler{log: log, ah: ah}
}

func (h *ProjectReconfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectReconfigHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	if err := h.ah.ReconfigProject(ctx, projectRef); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type ProjectUpdateRepoLinkedAccountHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectUpdateRepoLinkedAccountHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectUpdateRepoLinkedAccountHandler {
	return &ProjectUpdateRepoLinkedAccountHandler{log: log, ah: ah}
}

func (h *ProjectUpdateRepoLinkedAccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectUpdateRepoLinkedAccountHandler) do(r *http.Request) (*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	project, err := h.ah.ProjectUpdateRepoLinkedAccount(ctx, projectRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectResponse(project)

	return res, nil
}

type DeleteProjectHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteProjectHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: log, ah: ah}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteProjectHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	err = h.ah.DeleteProject(ctx, projectRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type ProjectHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectHandler {
	return &ProjectHandler{log: log, ah: ah}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectHandler) do(r *http.Request) (*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	project, err := h.ah.GetProject(ctx, projectRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectResponse(project)

	return res, nil
}

func createProjectResponse(r *csapitypes.Project) *gwapitypes.ProjectResponse {
	res := &gwapitypes.ProjectResponse{
		ID:                          r.ID,
		Name:                        r.Name,
		Path:                        r.Path,
		ParentPath:                  r.ParentPath,
		Visibility:                  gwapitypes.Visibility(r.Visibility),
		GlobalVisibility:            string(r.GlobalVisibility),
		PassVarsToForkedPR:          r.PassVarsToForkedPR,
		DefaultBranch:               r.DefaultBranch,
		MembersCanPerformRunActions: r.MembersCanPerformRunActions,
	}

	return res
}

type ProjectCreateRunHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectCreateRunHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectCreateRunHandler {
	return &ProjectCreateRunHandler{log: log, ah: ah}
}

func (h *ProjectCreateRunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectCreateRunHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var req gwapitypes.ProjectCreateRunRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	if err = h.ah.ProjectCreateRun(ctx, projectRef, req.Branch, req.Tag, req.Ref, req.CommitSHA); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type RefreshRemoteRepositoryInfoHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRefreshRemoteRepositoryInfoHandler(log zerolog.Logger, ah *action.ActionHandler) *RefreshRemoteRepositoryInfoHandler {
	return &RefreshRemoteRepositoryInfoHandler{log: log, ah: ah}
}

func (h *RefreshRemoteRepositoryInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RefreshRemoteRepositoryInfoHandler) do(r *http.Request) (*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	project, err := h.ah.RefreshRemoteRepositoryInfo(ctx, projectRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectResponse(project)

	return res, nil
}
