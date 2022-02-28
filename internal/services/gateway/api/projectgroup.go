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
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type CreateProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: log, ah: ah}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gwapitypes.CreateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user not authenticated")))
		return
	}

	creq := &action.CreateProjectGroupRequest{
		Name:          req.Name,
		ParentRef:     req.ParentRef,
		Visibility:    cstypes.Visibility(req.Visibility),
		CurrentUserID: userID,
	}

	projectGroup, err := h.ah.CreateProjectGroup(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateProjectGroupHandler {
	return &UpdateProjectGroupHandler{log: log, ah: ah}
}

func (h *UpdateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	var req gwapitypes.UpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteProjectGroupHandler {
	return &DeleteProjectGroupHandler{log: log, ah: ah}
}

func (h *DeleteProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	err = h.ah.DeleteProjectGroup(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type ProjectGroupHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: log, ah: ah}
}

func (h *ProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	projectGroup, err := h.ah.GetProjectGroup(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createProjectGroupResponse(projectGroup)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type ProjectGroupProjectsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupProjectsHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: log, ah: ah}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	csprojects, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	projects := make([]*gwapitypes.ProjectResponse, len(csprojects))
	for i, p := range csprojects {
		projects[i] = createProjectResponse(p)
	}

	if err := util.HTTPResponse(w, http.StatusOK, projects); err != nil {
		h.log.Err(err).Send()
	}
}

type ProjectGroupSubgroupsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectGroupSubgroupsHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: log, ah: ah}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	cssubgroups, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	subgroups := make([]*gwapitypes.ProjectGroupResponse, len(cssubgroups))
	for i, g := range cssubgroups {
		subgroups[i] = createProjectGroupResponse(g)
	}

	if err := util.HTTPResponse(w, http.StatusOK, subgroups); err != nil {
		h.log.Err(err).Send()
	}
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
