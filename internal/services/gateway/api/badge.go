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

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type BadgeHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewBadgeHandler(log zerolog.Logger, ah *action.ActionHandler) *BadgeHandler {
	return &BadgeHandler{log: log, ah: ah}
}

func (h *BadgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}
	branch := query.Get("branch")

	badge, err := h.ah.GetBadge(ctx, projectRef, branch)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	// TODO(sgotti) return some caching headers
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache")

	if _, err := w.Write([]byte(badge)); err != nil {
		h.log.Err(err).Send()
	}
}
