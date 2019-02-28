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
	"path"
)

var (
	// Storage paths. Always use path (not filepath) to use the "/" separator
	StorageDataDir          = "data"
	StorageProjectsDir      = path.Join(StorageDataDir, "projects")
	StorageUsersDir         = path.Join(StorageDataDir, "users")
	StorageOrgsDir          = path.Join(StorageDataDir, "orgs")
	StorageRemoteSourcesDir = path.Join(StorageDataDir, "remotesources")
)

const (
	etcdWalsMinRevisionRange = 100
)

func StorageProjectFile(projectID string) string {
	return path.Join(StorageProjectsDir, projectID)
}

func StorageUserFile(userID string) string {
	return path.Join(StorageUsersDir, userID)
}

func StorageOrgFile(orgID string) string {
	return path.Join(StorageOrgsDir, orgID)
}

func StorageRemoteSourceFile(userID string) string {
	return path.Join(StorageRemoteSourcesDir, userID)
}

type ConfigType string

const (
	ConfigTypeProject      ConfigType = "project"
	ConfigTypeUser         ConfigType = "user"
	ConfigTypeOrg          ConfigType = "org"
	ConfigTypeRemoteSource ConfigType = "remotesource"
)

func PathToTypeID(p string) (ConfigType, string) {
	var configType ConfigType
	switch path.Dir(p) {
	case StorageProjectsDir:
		configType = ConfigTypeProject
	case StorageUsersDir:
		configType = ConfigTypeUser
	case StorageOrgsDir:
		configType = ConfigTypeOrg
	case StorageRemoteSourcesDir:
		configType = ConfigTypeRemoteSource
	default:
		panic(fmt.Errorf("cannot determine configtype for path: %q", p))
	}

	return configType, path.Base(p)
}
