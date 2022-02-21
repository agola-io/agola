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

	"agola.io/agola/internal/services/gateway/action"
	util "agola.io/agola/internal/util"

	"github.com/rs/zerolog"
)

type VersionHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewVersionHandler(log zerolog.Logger, ah *action.ActionHandler) *VersionHandler {
	return &VersionHandler{log: log, ah: ah}
}

func (h *VersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	version, err := h.ah.GetVersion(ctx)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, version); err != nil {
		h.log.Err(err).Send()
	}
}
