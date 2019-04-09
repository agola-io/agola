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

	if err := httpResponse(w, http.StatusOK, project); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateProjectHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ch: ch}
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

	if err := httpResponse(w, http.StatusCreated, project); err != nil {
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
