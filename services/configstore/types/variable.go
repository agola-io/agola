// Copyright 2022 Sorint.lab
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
	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
)

type VariableValue struct {
	SecretName string `json:"secret_name,omitempty"`
	SecretVar  string `json:"secret_var,omitempty"`

	When *stypes.When `json:"when,omitempty"`
}

const (
	VariableKind    = "variable"
	VariableVersion = "v0.1.0"
)

type Variable struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Values []VariableValue `json:"values,omitempty"`
}

func NewVariable() *Variable {
	return &Variable{
		TypeMeta: stypes.TypeMeta{
			Kind:    VariableKind,
			Version: VariableVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
