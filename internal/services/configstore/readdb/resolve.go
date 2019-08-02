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

package readdb

import (
	"path"

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
	errors "golang.org/x/xerrors"
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
