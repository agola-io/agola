// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/common"
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

			// calculate global visibility
			visibility, err := getGlobalVisibility(readDB, tx, project.Visibility, &project.Parent)
			if err != nil {
				return err
			}

			// we calculate the path here from parent path since the db could not yet be
			// updated on create
			resProjects[i] = &Project{
				Project:          project,
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

	projectRefType, err := common.ParseRef(projectRef)
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var project *types.Project
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		switch projectRefType {
		case common.RefTypeID:
			project, err = h.readDB.GetProject(tx, projectRef)
		case common.RefTypePath:
			project, err = h.readDB.GetProjectByPath(tx, projectRef)
		}
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
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectHandler(logger *zap.Logger, ch *command.CommandHandler, readDB *readdb.ReadDB) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ch: ch, readDB: readDB}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.Project
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	project, err := h.ch.CreateProject(ctx, &req)
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
	ch  *command.CommandHandler
}

func NewDeleteProjectHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	err = h.ch.DeleteProject(ctx, projectRef)
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
