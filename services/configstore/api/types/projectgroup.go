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

// ProjectGroup augments cstypes.ProjectGroup with dynamic data
type ProjectGroup struct {
	*cstypes.ProjectGroup

	// dynamic data
	OwnerType        cstypes.ConfigType
	OwnerID          string
	Path             string
	ParentPath       string
	GlobalVisibility cstypes.Visibility
}
