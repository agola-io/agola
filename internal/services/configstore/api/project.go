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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// Project augments types.Project with dynamic data
type Project struct {
	*types.Project

	// dynamic data
	OwnerType        types.ConfigType
	OwnerID          string
	Path             string
	ParentPath       string
	GlobalVisibility types.Visibility
}

func projectResponse(readDB *readdb.ReadDB, project *types.Project) (*Project, error) {
	r, err := projectsResponse(readDB, []*types.Project{project})
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

func projectsResponse(readDB *readdb.ReadDB, projects []*types.Project) ([]*Project, error) {
	resProjects := make([]*Project, len(projects))

	err := readDB.Do(func(tx *db.Tx) error {
		for i, project := range projects {
			pp, err := readDB.GetPath(tx, project.Parent.Type, project.Parent.ID)
			if err != nil {
				return err
			}

			ownerType, ownerID, err := readDB.GetProjectOwnerID(tx, project)
			if err != nil {
				return err
			}

			// calculate global visibility
			visibility, err := getGlobalVisibility(readDB, tx, project.Visibility, &project.Parent)
			if err != nil {
				return err
			}

			// we calculate the path here from parent path since the db could not yet be
			// updated on create
			resProjects[i] = &Project{
				Project:          project,
				OwnerType:        ownerType,
				OwnerID:          ownerID,
				Path:             path.Join(pp, project.Name),
				ParentPath:       pp,
				GlobalVisibility: visibility,
			}
		}

		return nil
	})

	return resProjects, err
}

func getGlobalVisibility(readDB *readdb.ReadDB, tx *db.Tx, curVisibility types.Visibility, parent *types.Parent) (types.Visibility, error) {
	curParent := parent
	if curVisibility == types.VisibilityPrivate {
		return curVisibility, nil
	}

	for curParent.Type == types.ConfigTypeProjectGroup {
		projectGroup, err := readDB.GetProjectGroupByID(tx, curParent.ID)
		if err != nil {
			return "", err
		}
		if projectGroup.Visibility == types.VisibilityPrivate {
			curVisibility = types.VisibilityPrivate
			continue
		}

		curParent = &projectGroup.Parent
	}

	return curVisibility, nil
}

type ProjectHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectHandler {
	return &ProjectHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var project *types.Project
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProject(tx, projectRef)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if project == nil {
		httpError(w, util.NewErrNotFound(errors.Errorf("project %q doesn't exist", projectRef)))
		return
	}

	resProject, err := projectResponse(h.readDB, project)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resProject); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateProjectHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.Project
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, err := h.ah.CreateProject(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resProject, err := projectResponse(h.readDB, project)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, resProject); err != nil {
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
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultProjectsLimit = 10
	MaxProjectsLimit     = 20
)
