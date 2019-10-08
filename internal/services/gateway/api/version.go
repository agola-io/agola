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

	"go.uber.org/zap"
)

type VersionHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewVersionHandler(logger *zap.Logger, ah *action.ActionHandler) *VersionHandler {
	return &VersionHandler{log: logger.Sugar(), ah: ah}
}

func (h *VersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	version, err := h.ah.GetVersion(ctx)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, version); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
