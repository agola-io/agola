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
	"strings"

	"github.com/sorintlab/agola/internal/services/types"
)

func FilterOverridenVariables(variables []*types.Variable) []*types.Variable {
	variablesMap := map[string]*types.Variable{}
	for _, v := range variables {
		if _, ok := variablesMap[v.Name]; !ok {
			variablesMap[v.Name] = v
		}
	}

	filteredVariables := make([]*types.Variable, len(variablesMap))
	i := 0
	// keep the original order
	for _, v := range variables {
		if _, ok := variablesMap[v.Name]; !ok {
			continue
		}
		filteredVariables[i] = v
		delete(variablesMap, v.Name)
		i++
	}

	return filteredVariables
}

func GetVarValueMatchingSecret(varval types.VariableValue, varParentPath string, secrets []*types.Secret) *types.Secret {
	// get the secret value referenced by the variable, it must be a secret at the same level or a lower level
	var secret *types.Secret
	for _, s := range secrets {
		// we assume the root path will be the same
		if s.Name != varval.SecretName {
			continue
		}
		if strings.Contains(varParentPath, s.Parent.Path) {
			secret = s
			break
		}
	}

	return secret
}
