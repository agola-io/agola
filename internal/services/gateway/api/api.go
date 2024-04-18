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

	serrors "agola.io/agola/internal/services/errors"
	util "agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

const (
	DefaultLimit = 30
	MaxLimit     = 30
)

const (
	agolaCursorHeader = "X-Agola-Cursor"
)

func GetConfigTypeRef(r *http.Request) (cstypes.ObjectKind, string, error) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return "", "", util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("wrong projectref %q", vars["projectref"]))
	}
	if projectRef != "" {
		return cstypes.ObjectKindProject, projectRef, nil
	}

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return "", "", util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("wrong projectgroupref %q", vars["projectgroupref"]))
	}
	if projectGroupRef != "" {
		return cstypes.ObjectKindProjectGroup, projectGroupRef, nil
	}

	return "", "", util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("cannot get project or projectgroup ref"))
}

type requestOptions struct {
	Cursor string

	Limit         int
	SortDirection gwapitypes.SortDirection
}

func parseRequestOptions(r *http.Request) (*requestOptions, error) {
	query := r.URL.Query()

	cursor := query.Get("cursor")

	limit := DefaultLimit
	limitS := query.Get("limit")
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse limit"), serrors.InvalidLimit())
		}
	}
	if limit < 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("limit must be greater or equal than 0"), serrors.InvalidLimit())
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	sortDirection := gwapitypes.SortDirection(query.Get("sortdirection"))
	if sortDirection != "" {
		switch sortDirection {
		case gwapitypes.SortDirectionAsc:
		case gwapitypes.SortDirectionDesc:
		default:
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong sort direction %q", sortDirection), serrors.InvalidSortDirection())
		}
	}

	if cursor != "" && sortDirection != "" {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or sortdirection should be provided"))
	}

	return &requestOptions{
		Cursor: cursor,

		Limit:         limit,
		SortDirection: sortDirection,
	}, nil
}

type groupRunsRequestOptions struct {
	*requestOptions

	StartRunCounter uint64

	SubGroup     string
	PhaseFilter  []string
	ResultFilter []string
}

func parseGroupRunsRequestOptions(r *http.Request) (*groupRunsRequestOptions, error) {
	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	query := r.URL.Query()

	startRunCounterStr := query.Get("start")

	var startRunCounter uint64
	hasStartRunCounter := false
	if startRunCounterStr != "" {
		hasStartRunCounter = true

		var err error
		startRunCounter, err = strconv.ParseUint(startRunCounterStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run counter"), serrors.InvalidRunNumber())
		}
	}

	subGroup := query.Get("subgroup")
	phaseFilter := query["phase"]
	resultFilter := query["result"]

	if ropts.Cursor != "" {
		if hasStartRunCounter {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or start should be provided"))
		}
		if subGroup != "" {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or subgroup should be provided"))
		}
		if len(phaseFilter) > 0 {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or phaseFilter should be provided"))
		}
		if len(resultFilter) > 0 {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or resultFilter should be provided"))
		}
	}

	return &groupRunsRequestOptions{
		requestOptions: ropts,

		StartRunCounter: startRunCounter,

		SubGroup:     subGroup,
		PhaseFilter:  phaseFilter,
		ResultFilter: resultFilter,
	}, nil
}

func addCursorHeader(w http.ResponseWriter, cursor string) {
	w.Header().Add(agolaCursorHeader, cursor)
}
