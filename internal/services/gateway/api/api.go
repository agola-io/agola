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
	"encoding/json"
	"net/http"
	"net/url"

	util "agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"

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
	case util.IsBadRequest(err):
		var cerr *util.ErrBadRequest
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsNotExist(err):
		var cerr *util.ErrNotExist
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsForbidden(err):
		var cerr *util.ErrForbidden
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsUnauthorized(err):
		var cerr *util.ErrUnauthorized
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsInternal(err):
		var cerr *util.ErrInternal
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
	case util.IsBadRequest(err):
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(resj)
	case util.IsNotExist(err):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(resj)
	case util.IsForbidden(err):
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(resj)
	case util.IsUnauthorized(err):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(resj)
	case util.IsInternal(err):
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
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
		_, _ = w.Write(resj)
		return true
	}
	return false
}

func GetConfigTypeRef(r *http.Request) (cstypes.ConfigType, string, error) {
	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return "", "", util.NewErrBadRequest(errors.Errorf("wrong projectref %q: %w", vars["projectref"], err))
	}
	if projectRef != "" {
		return cstypes.ConfigTypeProject, projectRef, nil
	}

	projectGroupRef, err := url.PathUnescape(vars["projectgroupref"])
	if err != nil {
		return "", "", util.NewErrBadRequest(errors.Errorf("wrong projectgroupref %q: %w", vars["projectgroupref"], err))
	}
	if projectGroupRef != "" {
		return cstypes.ConfigTypeProjectGroup, projectGroupRef, nil
	}

	return "", "", util.NewErrBadRequest(errors.Errorf("cannot get project or projectgroup ref"))
}
