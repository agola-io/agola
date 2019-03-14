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

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var projectGroup *types.ProjectGroup
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if projectGroup == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroup); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type ProjectGroupProjectsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectGroupProjectsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectGroupProjectsHandler {
	return &ProjectGroupProjectsHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectGroupProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var projectGroup *types.ProjectGroup
	err = h.readDB.Do(func(tx *db.Tx) error {
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if projectGroup == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	var projects []*types.Project
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projects, err = h.readDB.GetProjectGroupProjects(tx, projectGroup.ID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(projects); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type ProjectGroupSubgroupsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectGroupSubgroupsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectGroupSubgroupsHandler {
	return &ProjectGroupSubgroupsHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectGroupSubgroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var projectGroup *types.ProjectGroup
	err = h.readDB.Do(func(tx *db.Tx) error {
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if projectGroup == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	var projectGroups []*types.ProjectGroup
	err = h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projectGroups, err = h.readDB.GetProjectGroupSubgroups(tx, projectGroup.ID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroups); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CreateProjectGroupHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectGroupHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateProjectGroupHandler {
	return &CreateProjectGroupHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateProjectGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.ProjectGroup
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	projectGroup, err := h.ch.CreateProjectGroup(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroup); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
