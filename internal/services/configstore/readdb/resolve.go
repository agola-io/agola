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
	"path"

	errors "golang.org/x/xerrors"
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

func (r *ReadDB) GetPath(tx *db.Tx, configType types.ConfigType, id string) (string, error) {
	var p string
	switch configType {
	case types.ConfigTypeProjectGroup:
		projectGroup, err := r.GetProjectGroup(tx, id)
		if err != nil {
			return "", err
		}
		if projectGroup == nil {
			return "", errors.Errorf("projectgroup with id %q doesn't exist", id)
		}
		p, err = r.GetProjectGroupPath(tx, projectGroup)
		if err != nil {
			return "", err
		}
	case types.ConfigTypeProject:
		project, err := r.GetProject(tx, id)
		if err != nil {
			return "", err
		}
		if project == nil {
			return "", errors.Errorf("project with id %q doesn't exist", id)
		}
		p, err = r.GetProjectPath(tx, project)
		if err != nil {
			return "", err
		}
	case types.ConfigTypeOrg:
		org, err := r.GetOrg(tx, id)
		if err != nil {
			return "", errors.Errorf("failed to get org %q: %w", id, err)
		}
		if org == nil {
			return "", errors.Errorf("cannot find org with id %q", id)
		}
		p = path.Join("org", org.Name)
	case types.ConfigTypeUser:
		user, err := r.GetUser(tx, id)
		if err != nil {
			return "", errors.Errorf("failed to get user %q: %w", id, err)
		}
		if user == nil {
			return "", errors.Errorf("cannot find user with id %q", id)
		}
		p = path.Join("user", user.Name)
	default:
		return "", errors.Errorf("config type %q doesn't provide a path", configType)
	}

	return p, nil
}
