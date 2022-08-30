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
	"io"
	"net/http"
	"net/url"

	util "agola.io/agola/internal/util"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type ReposHandler struct {
	log          zerolog.Logger
	gitServerURL string
}

func NewReposHandler(log zerolog.Logger, gitServerURL string) *ReposHandler {
	return &ReposHandler{log: log, gitServerURL: gitServerURL}
}

func (h *ReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	path := vars["rest"]

	u, err := url.Parse(h.gitServerURL)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}
	u.Path = path
	u.RawQuery = r.URL.RawQuery

	defer r.Body.Close()
	// proxy all the request body to the destination server
	req, err := http.NewRequest(r.Method, u.String(), r.Body)
	req = req.WithContext(ctx)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	// copy request headers
	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	// copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// copy status
	w.WriteHeader(resp.StatusCode)

	defer resp.Body.Close()
	// copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}
}
