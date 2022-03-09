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

package action

import (
	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/dbold"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/rs/zerolog"
)

type ActionHandler struct {
	log             zerolog.Logger
	readDB          *readdb.ReadDB
	dm              *datamanager.DataManager
	e               *etcd.Store
	maintenanceMode bool
}

func NewActionHandler(log zerolog.Logger, readDB *readdb.ReadDB, dm *datamanager.DataManager, e *etcd.Store) *ActionHandler {
	return &ActionHandler{
		log:             log,
		readDB:          readDB,
		dm:              dm,
		e:               e,
		maintenanceMode: false,
	}
}

func (h *ActionHandler) SetMaintenanceMode(maintenanceMode bool) {
	h.maintenanceMode = maintenanceMode
}

func (h *ActionHandler) ResolveConfigID(tx *db.Tx, configType types.ConfigType, ref string) (string, error) {
	switch configType {
	case types.ConfigTypeProjectGroup:
		group, err := h.readDB.GetProjectGroup(tx, ref)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if group == nil {
			return "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("group with ref %q doesn't exists", ref))
		}
		return group.ID, nil

	case types.ConfigTypeProject:
		project, err := h.readDB.GetProject(tx, ref)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if project == nil {
			return "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q doesn't exists", ref))
		}
		return project.ID, nil

	default:
		return "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("unknown config type %q", configType))
	}
}
