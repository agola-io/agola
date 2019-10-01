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
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type CreateProjectGroupHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gwapitypes.CreateProjectGroupRequest
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

	creq := &action.CreateProjectGroupRequest{
		Name:          req.Name,
		ParentRef:     req.ParentRef,
		Visibility:    cstypes.Visibility(req.Visibility),
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

	var req gwapitypes.UpdateProjectGroupRequest
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

	areq := &action.UpdateProjectGroupRequest{
		Name:       req.Name,
		ParentRef:  req.ParentRef,
		Visibility: visibility,
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

	projects := make([]*gwapitypes.ProjectResponse, len(csprojects))
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

	subgroups := make([]*gwapitypes.ProjectGroupResponse, len(cssubgroups))
	for i, g := range cssubgroups {
		subgroups[i] = createProjectGroupResponse(g)
	}

	if err := httpResponse(w, http.StatusOK, subgroups); err != nil {
		h.log.Errorf("err: %+v", err)
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
