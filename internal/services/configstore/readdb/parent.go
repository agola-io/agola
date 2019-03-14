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

package readdb

import (
	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
)

func (r *ReadDB) ResolveConfigID(tx *db.Tx, configType types.ConfigType, ref string) (string, error) {
	switch configType {
	case types.ConfigTypeProjectGroup:
		group, err := r.GetProjectGroup(tx, ref)
		if err != nil {
			return "", err
		}
		if group == nil {
			return "", util.NewErrBadRequest(errors.Errorf("group with ref %q doesn't exists", ref))
		}
		return group.ID, nil

	case types.ConfigTypeProject:
		project, err := r.GetProject(tx, ref)
		if err != nil {
			return "", err
		}
		if project == nil {
			return "", util.NewErrBadRequest(errors.Errorf("project with ref %q doesn't exists", ref))
		}
		return project.ID, nil

	default:
		return "", util.NewErrBadRequest(errors.Errorf("unknown config type %q", configType))
	}
}
