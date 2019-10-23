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

	itypes "agola.io/agola/internal/services/types"
)

func TestMatchWhen(t *testing.T) {
	tests := []struct {
		name    string
		when    *When
		refType itypes.RunRefType
		branch  string
		tag     string
		ref     string
		out     bool
	}{
		{
			name: "test no when, should always match",
			when: nil,
			out:  true,
		},
		{
			name: "test branch when include with empty match value, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     false,
		},
		{
			name: "test branch when include regexp with empty match value, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include with empty match value and empty provided branch, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "",
			out:     false,
		},
		{
			name: "test branch when include regexp with empty match value and empty provided branch, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "",
			out:     false,
		},
		{
			name: "test branch when include, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "branch01",
			out:     false,
		},
		{
			name: "test tag, ref when include, should not match since when is not nil and we have provided a branch and not a tag",
			when: &When{
				Tag: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
				Ref: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "branch01",
			out:     false,
		},
		{
			name: "test branch when include regexp, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "branch01",
			out:     false,
		},
		{
			name: "test branch when include regexp, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "branch01",
			out:     false,
		},
		{
			name: "test branch when include regexp, exclude simple, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "maste"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include regexp, exclude simple, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     false,
		},
		{
			name: "test branch when include regexp, exclude regexp, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "mb.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when include regexp, exclude regexp, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "ma.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     false,
		},
		{
			name: "test branch when multiple include regexp, multiple exclude regexp, should match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
						{Type: WhenConditionTypeRegExp, Match: "b.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "b.*"},
						{Type: WhenConditionTypeRegExp, Match: "c.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     true,
		},
		{
			name: "test branch when multiple include regexp, multiple exclude regexp, should not match",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "m.*"},
						{Type: WhenConditionTypeRegExp, Match: "b.*"},
					},
					Exclude: []WhenCondition{
						{Type: WhenConditionTypeRegExp, Match: "b.*"},
						{Type: WhenConditionTypeRegExp, Match: "ma.*"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			out:     false,
		},
		{
			name: "test only matching branch reftype",
			when: &When{
				Branch: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeTag,
			// we provide also a value to branch (should not be done)
			branch: "master",
			tag:    "master",
			out:    false,
		},
		{
			name: "test only matching tag reftype",
			when: &When{
				Tag: &WhenConditions{
					Include: []WhenCondition{
						{Type: WhenConditionTypeSimple, Match: "master"},
					},
				},
			},
			refType: itypes.RunRefTypeBranch,
			branch:  "master",
			// we provide also a value to tag (should not be done)
			tag: "master",
			out: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := MatchWhen(tt.when, tt.refType, tt.branch, tt.tag, tt.ref)
			if tt.out != out {
				t.Fatalf("expected match: %t, got: %t", tt.out, out)
			}
		})
	}
}
