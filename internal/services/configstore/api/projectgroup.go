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

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

func projectGroupResponse(projectGroup *types.ProjectGroup, projectGroupDynamicData *action.ProjectGroupDynamicData) (*csapitypes.ProjectGroup, error) {
	r, err := projectGroupsResponse([]*types.ProjectGroup{projectGroup}, map[string]*action.ProjectGroupDynamicData{projectGroup.ID: projectGroupDynamicData})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return r[0], nil
}

func projectGroupsResponse(projectGroups []*types.ProjectGroup, projectGroupsDynamicData map[string]*action.ProjectGroupDynamicData) ([]*csapitypes.ProjectGroup, error) {
	resProjectGroups := make([]*csapitypes.ProjectGroup, len(projectGroups))

	for i, projectGroup := range projectGroups {
		projectGroupDynamicData := projectGroupsDynamicData[projectGroup.ID]

		resProjectGroups[i] = &csapitypes.ProjectGroup{
			ProjectGroup:     projectGroup,
			OwnerType:        projectGroupDynamicData.OwnerType,
			OwnerID:          projectGroupDynamicData.OwnerID,
			Path:             projectGroupDynamicData.Path,
			ParentPath:       projectGroupDynamicData.ParentPath,
			GlobalVisibility: projectGroupDynamicData.GlobalVisibility,
		}
	}

	return resProjectGroups, nil
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

func (h *ProjectGroupHandler) do(r *http.Request) (*csapitypes.ProjectGroup, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	res, err := h.ah.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resProjectGroup, err := projectGroupResponse(res.ProjectGroup, res.ProjectGroupDynamicData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resProjectGroup, nil
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

func (h *ProjectGroupProjectsHandler) do(r *http.Request) ([]*csapitypes.Project, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	res, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resProjects, err := projectsResponse(res.Projects, res.ProjectsDynamicData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resProjects, nil
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

func (h *ProjectGroupSubgroupsHandler) do(r *http.Request) ([]*csapitypes.ProjectGroup, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	res, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resProjectGroups, err := projectGroupsResponse(res.ProjectGroups, res.ProjectGroupsDynamicData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resProjectGroups, nil
}

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

func (h *CreateProjectGroupHandler) do(r *http.Request) (*csapitypes.ProjectGroup, error) {
	ctx := r.Context()

	var req *csapitypes.CreateUpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateProjectGroupRequest{
		Name:       req.Name,
		Parent:     req.Parent,
		Visibility: req.Visibility,
	}

	res, err := h.ah.CreateProjectGroup(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resProjectGroup, err := projectGroupResponse(res.ProjectGroup, res.ProjectGroupDynamicData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resProjectGroup, nil
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

func (h *UpdateProjectGroupHandler) do(r *http.Request) (*csapitypes.ProjectGroup, error) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var req *csapitypes.CreateUpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateProjectGroupRequest{
		Name:       req.Name,
		Parent:     req.Parent,
		Visibility: req.Visibility,
	}

	res, err := h.ah.UpdateProjectGroup(ctx, projectGroupRef, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resProjectGroup, err := projectGroupResponse(res.ProjectGroup, res.ProjectGroupDynamicData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resProjectGroup, nil
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

	if err = h.ah.DeleteProjectGroup(ctx, projectGroupRef); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
