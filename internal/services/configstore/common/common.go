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

package common

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"
)

var (
	// Storage paths. Always use path (not filepath) to use the "/" separator
	StorageDataDir          = "data"
	StorageUsersDir         = path.Join(StorageDataDir, "users")
	StorageOrgsDir          = path.Join(StorageDataDir, "orgs")
	StorageProjectsDir      = path.Join(StorageDataDir, "projects")
	StorageProjectGroupsDir = path.Join(StorageDataDir, "projectgroups")
	StorageRemoteSourcesDir = path.Join(StorageDataDir, "remotesources")
)

const (
	etcdWalsMinRevisionRange = 100
)

func StorageUserFile(userID string) string {
	return path.Join(StorageUsersDir, userID)
}

func StorageOrgFile(orgID string) string {
	return path.Join(StorageOrgsDir, orgID)
}

func StorageProjectGroupFile(projectGroupID string) string {
	return path.Join(StorageProjectGroupsDir, projectGroupID)
}

func StorageProjectFile(projectID string) string {
	return path.Join(StorageProjectsDir, projectID)
}

func StorageRemoteSourceFile(userID string) string {
	return path.Join(StorageRemoteSourcesDir, userID)
}

func PathToTypeID(p string) (types.ConfigType, string) {
	var configType types.ConfigType
	switch path.Dir(p) {
	case StorageUsersDir:
		configType = types.ConfigTypeUser
	case StorageOrgsDir:
		configType = types.ConfigTypeOrg
	case StorageProjectGroupsDir:
		configType = types.ConfigTypeProjectGroup
	case StorageProjectsDir:
		configType = types.ConfigTypeProject
	case StorageRemoteSourcesDir:
		configType = types.ConfigTypeRemoteSource
	default:
		panic(fmt.Errorf("cannot determine configtype for path: %q", p))
	}

	return configType, path.Base(p)
}

type RefType int

const (
	RefTypeID RefType = iota
	RefTypePath
)

// ParseRef parses the api call to determine if the provided ref is
// an ID or a path
func ParseRef(projectRef string) (RefType, error) {
	projectRef, err := url.PathUnescape(projectRef)
	if err != nil {
		return -1, err
	}
	if strings.Contains(projectRef, "/") {
		return RefTypePath, nil
	}
	return RefTypeID, nil
}
