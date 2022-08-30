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
	"encoding/base64"
	"encoding/json"

	"agola.io/agola/internal/errors"
)

const (
	RunGenericSetupErrorName = "Setup Error"
)

type SortOrder int

const (
	SortOrderAsc SortOrder = iota
	SortOrderDesc
)

type RunBundle struct {
	Run *Run
	Rc  *RunConfig
}

type ChangeGroupsValues map[string]string

type ChangeGroupsUpdateToken struct {
	ChangeGroupsValues ChangeGroupsValues `json:"change_groups_values"`
}

func MarshalChangeGroupsUpdateToken(t *ChangeGroupsUpdateToken) (string, error) {
	tj, err := json.Marshal(t)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return base64.StdEncoding.EncodeToString(tj), nil
}

func UnmarshalChangeGroupsUpdateToken(s string) (*ChangeGroupsUpdateToken, error) {
	if s == "" {
		return nil, nil
	}

	tj, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var t *ChangeGroupsUpdateToken
	if err := json.Unmarshal(tj, &t); err != nil {
		return nil, errors.WithStack(err)
	}
	return t, nil
}
