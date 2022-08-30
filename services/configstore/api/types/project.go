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

package types

import (
	cstypes "agola.io/agola/services/configstore/types"
)

type CreateUpdateProjectRequest struct {
	Name                       string
	Parent                     cstypes.Parent
	Visibility                 cstypes.Visibility
	RemoteRepositoryConfigType cstypes.RemoteRepositoryConfigType
	RemoteSourceID             string
	LinkedAccountID            string
	RepositoryID               string
	RepositoryPath             string
	SSHPrivateKey              string
	SkipSSHHostKeyCheck        bool
	PassVarsToForkedPR         bool
	DefaultBranch              string
}

// Project augments cstypes.Project with dynamic data
type Project struct {
	*cstypes.Project

	// dynamic data
	OwnerType        cstypes.ObjectKind
	OwnerID          string
	Path             string
	ParentPath       string
	GlobalVisibility cstypes.Visibility
}
