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

package api

import (
	"net/http"
	"net/url"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func GetConfigTypeRef(r *http.Request) (types.ConfigType, string, error) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return "", "", util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "wrong projectref %q", vars["projectref"]))
	}
	if projectRef != "" {
		return types.ConfigTypeProject, projectRef, nil
	}

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return "", "", util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "wrong projectgroupref %q", vars["projectgroupref"]))
	}
	if projectGroupRef != "" {
		return types.ConfigTypeProjectGroup, projectGroupRef, nil
	}

	return "", "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot get project or projectgroup ref"))
}
