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
	"io"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type ReposHandler struct {
	log          *zap.SugaredLogger
	gitServerURL string
}

func NewReposHandler(logger *zap.Logger, gitServerURL string) *ReposHandler {
	return &ReposHandler{log: logger.Sugar(), gitServerURL: gitServerURL}
}

func (h *ReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	path := vars["rest"]

	h.log.Infof("path: %s", path)

	u, err := url.Parse(h.gitServerURL)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
	u.Path = path
	u.RawQuery = r.URL.RawQuery

	h.log.Infof("u: %s", u.String())
	// TODO(sgotti) Check authorized call from client

	defer r.Body.Close()
	// proxy all the request body to the destination server
	req, err := http.NewRequest(r.Method, u.String(), r.Body)
	req = req.WithContext(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}
