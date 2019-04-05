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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if projectGroup == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroup); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(projects); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(projectGroups); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}
