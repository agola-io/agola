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

type CreateProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: log, ah: ah}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateProjectGroupHandler) do(r *http.Request) (*gwapitypes.ProjectGroupResponse, error) {
	ctx := r.Context()

	var req gwapitypes.CreateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateProjectGroupRequest{
		Name:       req.Name,
		ParentRef:  req.ParentRef,
		Visibility: cstypes.Visibility(req.Visibility),
	}

	projectGroup, err := h.ah.CreateProjectGroup(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectGroupResponse(projectGroup)

	return res, nil
}

type UpdateProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateProjectGroupHandler {
	return &UpdateProjectGroupHandler{log: log, ah: ah}
}

func (h *UpdateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateProjectGroupHandler) do(r *http.Request) (*gwapitypes.ProjectGroupResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var req gwapitypes.UpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var visibility *cstypes.Visibility
	if req.Visibility != nil {
		v := cstypes.Visibility(*req.Visibility)
		visibility = &v
	}

	areq := &action.UpdateProjectGroupRequest{
		Name:       req.Name,
		ParentRef:  req.ParentRef,
		Visibility: visibility,
	}
	projectGroup, err := h.ah.UpdateProjectGroup(ctx, projectGroupRef, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectGroupResponse(projectGroup)

	return res, nil
}

type DeleteProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteProjectGroupHandler {
	return &DeleteProjectGroupHandler{log: log, ah: ah}
}

func (h *DeleteProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteProjectGroupHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	err = h.ah.DeleteProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type ProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: log, ah: ah}
}

func (h *ProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectGroupHandler) do(r *http.Request) (*gwapitypes.ProjectGroupResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	projectGroup, err := h.ah.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createProjectGroupResponse(projectGroup)

	return res, nil
}

type ProjectGroupProjectsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupProjectsHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: log, ah: ah}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectGroupProjectsHandler) do(r *http.Request) ([]*gwapitypes.ProjectResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	csprojects, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projects := make([]*gwapitypes.ProjectResponse, len(csprojects))
	for i, p := range csprojects {
		projects[i] = createProjectResponse(p)
	}

	return projects, nil
}

type ProjectGroupSubgroupsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupSubgroupsHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: log, ah: ah}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectGroupSubgroupsHandler) do(r *http.Request) ([]*gwapitypes.ProjectGroupResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	cssubgroups, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	subgroups := make([]*gwapitypes.ProjectGroupResponse, len(cssubgroups))
	for i, g := range cssubgroups {
		subgroups[i] = createProjectGroupResponse(g)
	}

	return subgroups, nil
}

func createProjectGroupResponse(r *csapitypes.ProjectGroup) *gwapitypes.ProjectGroupResponse {
	run := &gwapitypes.ProjectGroupResponse{
		ID:               r.ID,
		Name:             r.Name,
		Path:             r.Path,
		ParentPath:       r.ParentPath,
		Visibility:       gwapitypes.Visibility(r.Visibility),
		GlobalVisibility: string(r.GlobalVisibility),
	}

	return run
}
