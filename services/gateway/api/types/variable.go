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
	"agola.io/agola/services/types"
)

type VariableValueRequest struct {
	SecretName string `json:"secret_name"`
	SecretVar  string `json:"secret_var"`

	When *types.When `json:"when"`
}

type VariableValue struct {
	SecretName               string `json:"secret_name"`
	SecretVar                string `json:"secret_var"`
	MatchingSecretParentPath string `json:"matching_secret_parent_path"`

	When *types.When `json:"when"`
}

type VariableResponse struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Values     []VariableValue `json:"values"`
	ParentPath string          `json:"parent_path"`
}

type CreateVariableRequest struct {
	Name string `json:"name,omitempty"`

	Values []VariableValueRequest `json:"values,omitempty"`
}

type UpdateVariableRequest struct {
	Name string `json:"name,omitempty"`

	Values []VariableValueRequest `json:"values,omitempty"`
}
