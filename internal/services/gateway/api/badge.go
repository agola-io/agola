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
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"
)

type BadgeRequest struct {
	Name string `json:"name"`
}

type BadgeHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewBadgeHandler(logger *zap.Logger, ah *action.ActionHandler) *BadgeHandler {
	return &BadgeHandler{log: logger.Sugar(), ah: ah}
}

func (h *BadgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}
	branch := query.Get("branch")

	badge, err := h.ah.GetBadge(ctx, projectRef, branch)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	// TODO(sgotti) return some caching headers
	w.Header().Set("Content-Type", "image/svg+xml")

	if _, err := w.Write([]byte(badge)); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
