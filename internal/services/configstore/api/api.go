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
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

func GetObjectKindRef(r *http.Request) (types.ObjectKind, string, error) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return "", "", util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "wrong projectref %q", vars["projectref"]))
	}
	if projectRef != "" {
		return types.ObjectKindProject, projectRef, nil
	}

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return "", "", util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "wrong projectgroupref %q", vars["projectgroupref"]))
	}
	if projectGroupRef != "" {
		return types.ObjectKindProjectGroup, projectGroupRef, nil
	}

	return "", "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot get project or projectgroup ref"))
}

type requestOptions struct {
	Limit         int
	SortDirection types.SortDirection
}

func parseRequestOptions(r *http.Request) (*requestOptions, error) {
	query := r.URL.Query()

	limit := 0
	limitS := query.Get("limit")
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse limit"))
		}
	}
	if limit < 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("limit must be greater or equal than 0"))
	}

	sortDirection := types.SortDirection(query.Get("sortdirection"))
	if sortDirection != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
		case types.SortDirectionDesc:
		default:
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong sort direction %q", sortDirection))
		}
	}

	return &requestOptions{
		Limit:         limit,
		SortDirection: sortDirection,
	}, nil
}

func addHasMoreHeader(w http.ResponseWriter, hasMore bool) {
	w.Header().Add(agolaHasMoreHeader, strconv.FormatBool(hasMore))
}
