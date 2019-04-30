// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
)

func TestFilterOverridenVariables(t *testing.T) {
	tests := []struct {
		name      string
		variables []*csapi.Variable
		out       []*csapi.Variable
	}{
		{
			name:      "test empty variables",
			variables: []*csapi.Variable{},
			out:       []*csapi.Variable{},
		},
		{
			name: "test variable overrides",
			variables: []*csapi.Variable{
				// variables must be in depth (from leaves to root) order as returned by the
				// configstore apis
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var04",
					},
					ParentPath: "org/org01/projectgroup02/projectgroup03/project02",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var03",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01",
				},
			},
			out: []*csapi.Variable{
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var04",
					},
					ParentPath: "org/org01/projectgroup02/projectgroup03/project02",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var03",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var02",
					},
					ParentPath: "org/org01/projectgroup01/project01",
				},
				&csapi.Variable{
					Variable: &types.Variable{
						Name: "var01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := FilterOverridenVariables(tt.variables)

			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestGetVarValueMatchingSecret(t *testing.T) {
	tests := []struct {
		name          string
		varValue      types.VariableValue
		varParentPath string
		secrets       []*csapi.Secret
		out           *csapi.Secret
	}{
		{
			name: "test empty secrets",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/project01",
			secrets:       []*csapi.Secret{},
			out:           nil,
		},
		{
			name: "test secret with different name",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret02",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
			},
			out: nil,
		},
		{
			name: "test secret with tree",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret02",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup03",
				},
			},
			out: nil,
		},
		{
			name: "test secret in child of variable parent",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
			},
			out: nil,
		},
		{
			name: "test secret in same parent and also child of variable parent",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
			},
			out: &csapi.Secret{
				Secret: &types.Secret{
					Name: "secret01",
				},
				ParentPath: "org/org01/projectgroup01/projectgroup02",
			},
		},
		{
			name: "test secret in parent",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
			out: &csapi.Secret{
				Secret: &types.Secret{
					Name: "secret01",
				},
				ParentPath: "org/org01/projectgroup01",
			},
		},
		{
			name: "test multiple secrets in same branch and also child of variable parent",
			varValue: types.VariableValue{
				SecretName: "secret01",
				SecretVar:  "secretvar01",
			},
			varParentPath: "org/org01/projectgroup01/projectgroup02",
			secrets: []*csapi.Secret{
				// secrets must be in depth (from leaves to root) order as returned by the
				// configstore apis
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02/project01",
				},
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01/projectgroup02",
				},
				&csapi.Secret{
					Secret: &types.Secret{
						Name: "secret01",
					},
					ParentPath: "org/org01/projectgroup01",
				},
			},
			out: &csapi.Secret{
				Secret: &types.Secret{
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
