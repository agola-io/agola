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

type CreateProjectGroupRequest struct {
	Name       string     `json:"name"`
	ParentRef  string     `json:"parent_ref"`
	Visibility Visibility `json:"visibility"`
}

type UpdateProjectGroupRequest struct {
	Name       *string     `json:"name,omitempty"`
	ParentRef  *string     `json:"parent_ref,omitempty"`
	Visibility *Visibility `json:"visibility,omitempty"`
}

type ProjectGroupResponse struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Path             string     `json:"path"`
	ParentPath       string     `json:"parent_path"`
	Visibility       Visibility `json:"visibility"`
	GlobalVisibility string     `json:"global_visibility"`
}
