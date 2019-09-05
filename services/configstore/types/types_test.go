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
	"testing"

	"agola.io/agola/services/types"
)

func TestMatchWhen(t *testing.T) {
	tests := []struct {
		name   string
		when   *types.When
		branch string
		tag    string
		ref    string
		out    bool
	}{
		{
			name: "test no when, should always match",
			when: nil,
			out:  true,
		},
		{
			name: "test branch when include with empty match value, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple},
					},
				},
			},
			branch: "master",
			out:    false,
		},
		{
			name: "test branch when include regexp with empty match value, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include with empty match value and empty provided branch, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple},
					},
				},
			},
			branch: "",
			out:    false,
		},
		{
			name: "test branch when include regexp with empty match value and empty provided branch, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp},
					},
				},
			},
			branch: "",
			out:    false,
		},
		{
			name: "test branch when include, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			branch: "branch01",
			out:    false,
		},
		{
			name: "test tag, ref when include, should not match since when is not nil and we have provided a branch and not a tag",
			when: &types.When{
				Tag: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "master"},
					},
				},
				Ref: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			branch: "branch01",
			out:    false,
		},
		{
			name: "test branch when include regexp, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "master"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "master"},
					},
				},
			},
			branch: "branch01",
			out:    false,
		},
		{
			name: "test branch when include regexp, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
				},
			},
			branch: "branch01",
			out:    false,
		},
		{
			name: "test branch when include regexp, exclude simple, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "maste"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include regexp, exclude simple, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			branch: "master",
			out:    false,
		},
		{
			name: "test branch when include regexp, exclude regexp, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "mb.*"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when include regexp, exclude regexp, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "ma.*"},
					},
				},
			},
			branch: "master",
			out:    false,
		},
		{
			name: "test branch when multiple include regexp, multiple exclude regexp, should match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
						{Type: types.WhenConditionTypeRegExp, Match: "b.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "b.*"},
						{Type: types.WhenConditionTypeRegExp, Match: "c.*"},
					},
				},
			},
			branch: "master",
			out:    true,
		},
		{
			name: "test branch when multiple include regexp, multiple exclude regexp, should not match",
			when: &types.When{
				Branch: &types.WhenConditions{
					Include: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "m.*"},
						{Type: types.WhenConditionTypeRegExp, Match: "b.*"},
					},
					Exclude: []types.WhenCondition{
						{Type: types.WhenConditionTypeRegExp, Match: "b.*"},
						{Type: types.WhenConditionTypeRegExp, Match: "ma.*"},
					},
				},
			},
			branch: "master",
			out:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := types.MatchWhen(tt.when, tt.branch, tt.tag, tt.ref)
			if tt.out != out {
				t.Fatalf("expected match: %t, got: %t", tt.out, out)
			}
		})
	}
}
