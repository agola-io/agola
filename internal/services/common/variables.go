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
	csapi "agola.io/agola/internal/services/configstore/api"
	cstypes "agola.io/agola/internal/services/configstore/types"
	"agola.io/agola/internal/util"
)

func FilterOverriddenVariables(variables []*csapi.Variable) []*csapi.Variable {
	variablesMap := map[string]*csapi.Variable{}
	for _, v := range variables {
		if _, ok := variablesMap[v.Name]; !ok {
			variablesMap[v.Name] = v
		}
	}

	filteredVariables := make([]*csapi.Variable, len(variablesMap))
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

func GetVarValueMatchingSecret(varval cstypes.VariableValue, varParentPath string, secrets []*csapi.Secret) *csapi.Secret {
	// get the secret value referenced by the variable, it must be a secret at the same level or a lower level
	var secret *csapi.Secret
	for _, s := range secrets {
		// we assume the root path will be the same
		if s.Name != varval.SecretName {
			continue
		}
		if util.IsSameOrParentPath(s.ParentPath, varParentPath) {
			secret = s
			break
		}
	}

	return secret
}
