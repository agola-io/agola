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

package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	errors "golang.org/x/xerrors"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func ErrorResponseFromError(err error) *ErrorResponse {
	var aerr error
	// use inner errors if of these types
	switch {
	case errors.Is(err, &util.ErrBadRequest{}):
		var cerr *util.ErrBadRequest
		errors.As(err, &cerr)
		aerr = cerr
	case errors.Is(err, &util.ErrNotFound{}):
		var cerr *util.ErrNotFound
		errors.As(err, &cerr)
		aerr = cerr
	case errors.Is(err, &util.ErrForbidden{}):
		var cerr *util.ErrForbidden
		errors.As(err, &cerr)
		aerr = cerr
	case errors.Is(err, &util.ErrUnauthorized{}):
		var cerr *util.ErrUnauthorized
		errors.As(err, &cerr)
		aerr = cerr
	}

	if aerr != nil {
		return &ErrorResponse{Message: aerr.Error()}
	}

	// on generic error return an generic message to not leak the real error
	return &ErrorResponse{Message: "internal server error"}
}

func httpError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	response := ErrorResponseFromError(err)
	resj, merr := json.Marshal(response)
	if merr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}
	switch {
	case errors.Is(err, &util.ErrBadRequest{}):
		w.WriteHeader(http.StatusBadRequest)
		w.Write(resj)
	case errors.Is(err, &util.ErrNotFound{}):
		w.WriteHeader(http.StatusNotFound)
		w.Write(resj)
	case errors.Is(err, &util.ErrForbidden{}):
		w.WriteHeader(http.StatusForbidden)
		w.Write(resj)
	case errors.Is(err, &util.ErrUnauthorized{}):
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resj)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(resj)
	}
	return true
}

func httpResponse(w http.ResponseWriter, code int, res interface{}) error {
	w.Header().Set("Content-Type", "application/json")

	if res != nil {
		resj, err := json.Marshal(res)
		if err != nil {
			httpError(w, err)
			return err
		}
		w.WriteHeader(code)
		_, err = w.Write(resj)
		return err
	}

	w.WriteHeader(code)
	return nil
}

func httpErrorFromRemote(w http.ResponseWriter, resp *http.Response, err error) bool {
	if err != nil {
		// on generic error return an generic message to not leak the real error
		response := &ErrorResponse{Message: "internal server error"}
		if resp != nil {
			response = &ErrorResponse{Message: err.Error()}
		}
		resj, merr := json.Marshal(response)
		if merr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		if resp != nil {
			w.WriteHeader(resp.StatusCode)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Write(resj)
		return true
	}
	return false
}

func GetConfigTypeRef(r *http.Request) (types.ConfigType, string, error) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return "", "", util.NewErrBadRequest(errors.Errorf("wrong projectref %q: %w", vars["projectref"], err))
	}
	if projectRef != "" {
		return types.ConfigTypeProject, projectRef, nil
	}

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return "", "", util.NewErrBadRequest(errors.Errorf("wrong projectgroupref %q: %w", vars["projectgroupref"], err))
	}
	if projectGroupRef != "" {
		return types.ConfigTypeProjectGroup, projectGroupRef, nil
	}

	return "", "", util.NewErrBadRequest(errors.Errorf("cannot get project or projectgroup ref"))
}
