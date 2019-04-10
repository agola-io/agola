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

package executor

import (
	"encoding/base64"
	"encoding/json"

	"github.com/sorintlab/agola/internal/services/runservice/types"

	dtypes "github.com/docker/docker/api/types"
	"github.com/pkg/errors"
)

func registryAuthToken(auth *types.RegistryAuth) (string, error) {
	if auth == nil {
		return "", nil
	}

	switch auth.Type {
	case types.RegistryAuthTypeDefault:
		authConfig := dtypes.AuthConfig{
			Username: auth.Username,
			Password: auth.Password,
		}
		authConfigj, err := json.Marshal(authConfig)
		if err != nil {
			panic(err)
		}
		return base64.URLEncoding.EncodeToString(authConfigj), nil

	default:
		return "", errors.Errorf("unsupported registry auth type %q", auth.Type)
	}
}
