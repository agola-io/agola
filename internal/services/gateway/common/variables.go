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
