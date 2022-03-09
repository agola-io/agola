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

func projectResponse(ctx context.Context, readDB *readdb.ReadDB, project *types.Project) (*csapitypes.Project, error) {
	r, err := projectsResponse(ctx, readDB, []*types.Project{project})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return r[0], nil
}

func projectsResponse(ctx context.Context, readDB *readdb.ReadDB, projects []*types.Project) ([]*csapitypes.Project, error) {
	resProjects := make([]*csapitypes.Project, len(projects))

	err := readDB.Do(ctx, func(tx *db.Tx) error {
		for i, project := range projects {
			pp, err := readDB.GetPath(tx, project.Parent.Type, project.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}

			ownerType, ownerID, err := readDB.GetProjectOwnerID(tx, project)
			if err != nil {
				return errors.WithStack(err)
			}

			// calculate global visibility
			visibility, err := getGlobalVisibility(readDB, tx, project.Visibility, &project.Parent)
			if err != nil {
				return errors.WithStack(err)
			}

			// we calculate the path here from parent path since the db could not yet be
			// updated on create
			resProjects[i] = &csapitypes.Project{
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

	return resProjects, errors.WithStack(err)
}

func getGlobalVisibility(readDB *readdb.ReadDB, tx *db.Tx, curVisibility types.Visibility, parent *types.Parent) (types.Visibility, error) {
	curParent := parent
	if curVisibility == types.VisibilityPrivate {
		return curVisibility, nil
	}

	for curParent.Type == types.ConfigTypeProjectGroup {
		projectGroup, err := readDB.GetProjectGroupByID(tx, curParent.ID)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if projectGroup.Visibility == types.VisibilityPrivate {
			return types.VisibilityPrivate, nil
		}

		curParent = &projectGroup.Parent
	}

	// check parent visibility
	if curParent.Type == types.ConfigTypeOrg {
		org, err := readDB.GetOrg(tx, curParent.ID)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if org.Visibility == types.VisibilityPrivate {
			return types.VisibilityPrivate, nil
		}
	}

	return curVisibility, nil
}

type ProjectHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewProjectHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *ProjectHandler {
	return &ProjectHandler{log: log, ah: ah, readDB: readDB}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	project, err := h.ah.GetProject(ctx, projectRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProject, err := projectResponse(ctx, h.readDB, project)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resProject); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateProjectHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *CreateProjectHandler {
	return &CreateProjectHandler{log: log, ah: ah, readDB: readDB}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateUpdateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateProjectRequest{
		Name:                       req.Name,
		Parent:                     req.Parent,
		Visibility:                 req.Visibility,
		RemoteRepositoryConfigType: req.RemoteRepositoryConfigType,
		RemoteSourceID:             req.RemoteSourceID,
		LinkedAccountID:            req.LinkedAccountID,
		RepositoryID:               req.RepositoryID,
		RepositoryPath:             req.RepositoryPath,
		SSHPrivateKey:              req.SSHPrivateKey,
		SkipSSHHostKeyCheck:        req.SkipSSHHostKeyCheck,
		PassVarsToForkedPR:         req.PassVarsToForkedPR,
	}

	project, err := h.ah.CreateProject(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProject, err := projectResponse(ctx, h.readDB, project)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, resProject); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateProjectHandler struct {
	log    zerolog.Logger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewUpdateProjectHandler(log zerolog.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *UpdateProjectHandler {
	return &UpdateProjectHandler{log: log, ah: ah, readDB: readDB}
}

func (h *UpdateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	var req *csapitypes.CreateUpdateProjectRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateProjectRequest{
		Name:                       req.Name,
		Parent:                     req.Parent,
		Visibility:                 req.Visibility,
		RemoteRepositoryConfigType: req.RemoteRepositoryConfigType,
		RemoteSourceID:             req.RemoteSourceID,
		LinkedAccountID:            req.LinkedAccountID,
		RepositoryID:               req.RepositoryID,
		RepositoryPath:             req.RepositoryPath,
		SSHPrivateKey:              req.SSHPrivateKey,
		SkipSSHHostKeyCheck:        req.SkipSSHHostKeyCheck,
		PassVarsToForkedPR:         req.PassVarsToForkedPR,
	}

	project, err := h.ah.UpdateProject(ctx, projectRef, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resProject, err := projectResponse(ctx, h.readDB, project)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, resProject); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteProjectHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteProjectHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: log, ah: ah}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	err = h.ah.DeleteProject(ctx, projectRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

const (
	DefaultProjectsLimit = 10
	MaxProjectsLimit     = 20
)
