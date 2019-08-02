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
	"testing"

	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	"github.com/google/go-cmp/cmp"
)

func TestFilterOverriddenVariables(t *testing.T) {
	tests := []struct {
		name      string
		variables []*csapitypes.Variable
		out       []*csapitypes.Variable
	}{
		{
			name:      "test empty variables",
			variables: []*csapitypes.Variable{},
			out:       []*csapitypes.Variable{},
		},
		{
			name: "test variable overrides",
			variables: []*csapitypes.Variable{
				// variables must be in depth (from leaves to root) order as returned by the
				// configstore apis
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var04",
					},
					ParentPath: "org/org01/projectgroup02/projectgroup03/project02",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var03",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01",
				},
			},
			out: []*csapitypes.Variable{
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var04",
					},
					ParentPath: "org/org01/projectgroup02/projectgroup03/project02",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var03",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapitypes.Variable{
					Variable: &cstypes.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := FilterOverriddenVariables(tt.variables)

			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestGetVarValueMatchingSecret(t *testing.T) {
	tests := []struct {
		name          string
		varValue      cstypes.VariableValue
		varParentPath string
		secrets       []*csapitypes.Secret
		out           *csapitypes.Secret
	}{
		{
			name: "test empty secrets",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/project01",
			secrets:       []*csapitypes.Secret{},
			out:           nil,
		},
		{
			name: "test secret with different name",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret02",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
			},
			out: nil,
		},
		{
			name: "test secret with tree",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret02",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup03",
				},
			},
			out: nil,
		},
		{
			name: "test secret in child of variable parent",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
			},
			out: nil,
		},
		{
			name: "test secret in same parent and also child of variable parent",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
			},
			out: &csapitypes.Secret{
				Secret: &cstypes.Secret{
					Name: "secret01",
				},
				ParentPath: "org/org01/projectgroup01/projectgroup02",
			},
		},
		{
			name: "test secret in parent",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
			out: &csapitypes.Secret{
				Secret: &cstypes.Secret{
					Name: "secret01",
				},
				ParentPath: "org/org01/projectgroup01",
			},
		},
		{
			name: "test multiple secrets in same branch and also child of variable parent",
			varValue: cstypes.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapitypes.Secret{
				// secrets must be in depth (from leaves to root) order as returned by the
				// configstore apis
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
				&csapitypes.Secret{
					Secret: &cstypes.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
			out: &csapitypes.Secret{
				Secret: &cstypes.Secret{
					Name: "secret01",
				},
				ParentPath: "org/org01/projectgroup01/projectgroup02",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := GetVarValueMatchingSecret(tt.varValue, tt.varParentPath, tt.secrets)

			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}
