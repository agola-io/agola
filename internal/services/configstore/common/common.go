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
	StorageSecretsDir       = path.Join(StorageDataDir, "secrets")
	StorageVariablesDir     = path.Join(StorageDataDir, "variables")
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

func StorageSecretFile(secretID string) string {
	return path.Join(StorageSecretsDir, secretID)
}

func StorageVariableFile(variableID string) string {
	return path.Join(StorageVariablesDir, variableID)
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
	case StorageSecretsDir:
		configType = types.ConfigTypeSecret
	case StorageVariablesDir:
		configType = types.ConfigTypeVariable
	default:
		panic(fmt.Errorf("cannot determine configtype for path: %q", p))
	}

	return configType, path.Base(p)
}

func DataToPathFunc(dataType string, id string) string {
	switch types.ConfigType(dataType) {
	case types.ConfigTypeUser:
		return StorageUserFile(id)
	case types.ConfigTypeOrg:
		return StorageOrgFile(id)
	case types.ConfigTypeProjectGroup:
		return StorageProjectGroupFile(id)
	case types.ConfigTypeProject:
		return StorageProjectFile(id)
	case types.ConfigTypeRemoteSource:
		return StorageRemoteSourceFile(id)
	case types.ConfigTypeSecret:
		return StorageSecretFile(id)
	case types.ConfigTypeVariable:
		return StorageVariableFile(id)
	}

	panic(fmt.Errorf("unknown data type %q", dataType))
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
