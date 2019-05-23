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
	"path"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// ProjectGroup augments types.ProjectGroup with dynamic data
type ProjectGroup struct {
	*types.ProjectGroup

	// dynamic data
	OwnerType        types.ConfigType
	OwnerID          string
	Path             string
	ParentPath       string
	GlobalVisibility types.Visibility
}

func projectGroupResponse(readDB *readdb.ReadDB, projectGroup *types.ProjectGroup) (*ProjectGroup, error) {
	r, err := projectGroupsResponse(readDB, []*types.ProjectGroup{projectGroup})
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

func projectGroupsResponse(readDB *readdb.ReadDB, projectGroups []*types.ProjectGroup) ([]*ProjectGroup, error) {
	resProjectGroups := make([]*ProjectGroup, len(projectGroups))

	err := readDB.Do(func(tx *db.Tx) error {
		for i, projectGroup := range projectGroups {
			pp, err := readDB.GetPath(tx, projectGroup.Parent.Type, projectGroup.Parent.ID)
			if err != nil {
				return err
			}

			ownerType, ownerID, err := readDB.GetProjectGroupOwnerID(tx, projectGroup)
			if err != nil {
				return err
			}

			// calculate global visibility
			visibility, err := getGlobalVisibility(readDB, tx, projectGroup.Visibility, &projectGroup.Parent)
			if err != nil {
				return err
			}

			// we calculate the path here from parent path since the db could not yet be
			// updated on create
			resProjectGroups[i] = &ProjectGroup{
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

	return resProjectGroups, err
}

type ProjectGroupHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectGroupHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectGroupHandler {
	return &ProjectGroupHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var projectGroup *types.ProjectGroup
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if projectGroup == nil {
		httpError(w, util.NewErrNotFound(errors.Errorf("project group %q doesn't exist", projectGroupRef)))
		return
	}

	resProjectGroup, err := projectGroupResponse(h.readDB, projectGroup)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resProjectGroup); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectGroupProjectsHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectGroupProjectsHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	projects, err := h.ah.GetProjectGroupProjects(ctx, projectGroupRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resProjects, err := projectsResponse(h.readDB, projects)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resProjects); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ProjectGroupSubgroupsHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectGroupSubgroupsHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	projectGroups, err := h.ah.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resProjectGroups, err := projectGroupsResponse(h.readDB, projectGroups)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resProjectGroups); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateProjectGroupHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.ProjectGroup
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	projectGroup, err := h.ah.CreateProjectGroup(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resProjectGroup, err := projectGroupResponse(h.readDB, projectGroup)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, resProjectGroup); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateProjectGroupHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewUpdateProjectGroupHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *UpdateProjectGroupHandler {
	return &UpdateProjectGroupHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *UpdateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var projectGroup *types.ProjectGroup
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&projectGroup); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	areq := &action.UpdateProjectGroupRequest{
		ProjectGroupRef: projectGroupRef,
		ProjectGroup:    projectGroup,
	}
	projectGroup, err = h.ah.UpdateProjectGroup(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resProjectGroup, err := projectGroupResponse(h.readDB, projectGroup)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, resProjectGroup); err != nil {
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
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
