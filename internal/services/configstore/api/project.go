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
	"strconv"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type GetProjectHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewGetProjectHandler(logger *zap.Logger, readDB *readdb.ReadDB) *GetProjectHandler {
	return &GetProjectHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *GetProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID := vars["projectid"]

	var project *types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProject(tx, projectID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if project == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type GetProjectByNameHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewGetProjectByNameHandler(logger *zap.Logger, readDB *readdb.ReadDB) *GetProjectByNameHandler {
	return &GetProjectByNameHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *GetProjectByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["projectname"]

	var project *types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProjectByName(tx, projectName)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if project == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	project, err := h.ch.CreateProject(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	projectName := vars["projectname"]

	if err := h.ch.DeleteProject(ctx, projectName); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

const (
	DefaultProjectsLimit = 10
	MaxProjectsLimit     = 20
)

type ProjectsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectsHandler {
	return &ProjectsHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultProjectsLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}
	if limit < 0 {
		http.Error(w, "limit must be greater or equal than 0", http.StatusBadRequest)
		return
	}
	if limit > MaxProjectsLimit {
		limit = MaxProjectsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	projects, err := h.readDB.GetProjects(start, limit, asc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(projects); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
