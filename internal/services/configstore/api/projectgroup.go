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
	"net/http"
	"net/url"
	"path"

	"agola.io/agola/internal/dbold"
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func projectGroupResponse(ctx context.Context, readDB *readdb.ReadDB, projectGroup *types.ProjectGroup) (*csapitypes.ProjectGroup, error) {
	r, err := projectGroupsResponse(ctx, readDB, []*types.ProjectGroup{projectGroup})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return r[0], nil
}

func projectGroupsResponse(ctx context.Context, readDB *readdb.ReadDB, projectGroups []*types.ProjectGroup) ([]*csapitypes.ProjectGroup, error) {
	resProjectGroups := make([]*csapitypes.ProjectGroup, len(projectGroups))

	err := readDB.Do(ctx, func(tx *db.Tx) error {
		for i, projectGroup := range projectGroups {
			pp, err := readDB.GetPath(tx, projectGroup.Parent.Type, projectGroup.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}

			ownerType, ownerID, err := readDB.GetProjectGroupOwnerID(tx, projectGroup)
			if err != nil {
				return errors.WithStack(err)
			}

			// calculate global visibility
			visibility, err := getGlobalVisibility(readDB, tx, projectGroup.Visibility, &projectGroup.Parent)
			if err != nil {
				return errors.WithStack(err)
			}

			// we calculate the path here from parent path since the db could not yet be
			// updated on create
			resProjectGroups[i] = &csapitypes.ProjectGroup{
				ProjectGroup:     projectGroup,
				OwnerType:        ownerType,
				OwnerID:          ownerID,
				Path:             path.Join(pp, projectGroup.Name),
				ParentPath:       pp,
				GlobalVisibility: visibility,
			}

		}
		return nil
	})

	return resProjectGroups, errors.WithStack(err)
}

type ProjectGroupHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: log, ah: ah, readDB: readDB}
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

	resProjectGroup, err := projectGroupResponse(ctx, h.readDB, projectGroup)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resProjectGroup); err != nil {
		h.log.Err(err).Send()
	}
}

type ProjectGroupProjectsHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectGroupProjectsHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: log, ah: ah, readDB: readDB}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	projects, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProjects, err := projectsResponse(ctx, h.readDB, projects)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resProjects); err != nil {
		h.log.Err(err).Send()
	}
}

type ProjectGroupSubgroupsHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectGroupSubgroupsHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: log, ah: ah, readDB: readDB}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	projectGroups, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProjectGroups, err := projectGroupsResponse(ctx, h.readDB, projectGroups)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resProjectGroups); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateProjectGroupHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: log, ah: ah, readDB: readDB}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateUpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateProjectGroupRequest{
		Name:       req.Name,
		Parent:     req.Parent,
		Visibility: req.Visibility,
	}

	projectGroup, err := h.ah.CreateProjectGroup(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProjectGroup, err := projectGroupResponse(ctx, h.readDB, projectGroup)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, resProjectGroup); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateProjectGroupHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewUpdateProjectGroupHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *UpdateProjectGroupHandler {
	return &UpdateProjectGroupHandler{log: log, ah: ah, readDB: readDB}
}

func (h *UpdateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	var req *csapitypes.CreateUpdateProjectGroupRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateProjectGroupRequest{
		Name:       req.Name,
		Parent:     req.Parent,
		Visibility: req.Visibility,
	}

	projectGroup, err := h.ah.UpdateProjectGroup(ctx, projectGroupRef, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProjectGroup, err := projectGroupResponse(ctx, h.readDB, projectGroup)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, resProjectGroup); err != nil {
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
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
