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
	"regexp"

	itypes "agola.io/agola/internal/services/types"
)

type When struct {
	Branch *WhenConditions `json:"branch,omitempty"`
	Tag    *WhenConditions `json:"tag,omitempty"`
	Ref    *WhenConditions `json:"ref,omitempty"`
}

type WhenConditions struct {
	Include []WhenCondition `json:"include,omitempty"`
	Exclude []WhenCondition `json:"exclude,omitempty"`
}

type WhenConditionType string

const (
	WhenConditionTypeSimple WhenConditionType = "simple"
	WhenConditionTypeRegExp WhenConditionType = "regexp"
)

type WhenCondition struct {
	Type  WhenConditionType `json:"type,omitempty"`
	Match string            `json:"match,omitempty"`
}

func MatchWhen(when *When, refType itypes.RunRefType, branch, tag, ref string) bool {
	include := true
	if when != nil {
		include = false
		// test only if branch is not empty, if empty mean that we are not in a branch
		if refType == itypes.RunRefTypeBranch && when.Branch != nil && branch != "" {
			// first check includes and override with excludes
			if matchCondition(when.Branch.Include, branch) {
				include = true
			}
			if matchCondition(when.Branch.Exclude, branch) {
				include = false
			}
		}
		// test only if tag is not empty, if empty mean that we are not in a tag
		if refType == itypes.RunRefTypeTag && when.Tag != nil && tag != "" {
			// first check includes and override with excludes
			if matchCondition(when.Tag.Include, tag) {
				include = true
			}
			if matchCondition(when.Tag.Exclude, tag) {
				include = false
			}
		}
		// we assume that ref always have a value
		if when.Ref != nil {
			// first check includes and override with excludes
			if matchCondition(when.Ref.Include, ref) {
				include = true
			}
			if matchCondition(when.Ref.Exclude, ref) {
				include = false
			}
		}
	}

	return include
}

func matchCondition(conds []WhenCondition, s string) bool {
	for _, cond := range conds {
		switch cond.Type {
		case WhenConditionTypeSimple:
			if cond.Match == s {
				return true
			}
		case WhenConditionTypeRegExp:
			re, err := regexp.Compile(cond.Match)
			if err != nil {
				panic(err)
			}
			if re.MatchString(s) {
				return true
			}
		}
	}
	return false
}
