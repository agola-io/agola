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

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/services/runservice/action"

	"go.uber.org/zap"
)

type MaintenanceModeHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
	e   *etcd.Store
}

func NewMaintenanceModeHandler(logger *zap.Logger, ah *action.ActionHandler, e *etcd.Store) *MaintenanceModeHandler {
	return &MaintenanceModeHandler{log: logger.Sugar(), ah: ah, e: e}
}

func (h *MaintenanceModeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	enable := false
	switch r.Method {
	case "PUT":
		enable = true
	case "DELETE":
		enable = false
	}

	err := h.ah.MaintenanceMode(ctx, enable)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := httpResponse(w, http.StatusOK, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}

}

type ExportHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewExportHandler(logger *zap.Logger, ah *action.ActionHandler) *ExportHandler {
	return &ExportHandler{log: logger.Sugar(), ah: ah}
}

func (h *ExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.ah.Export(ctx, w)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		// since we already answered with a 200 we cannot return another error code
		// So abort the connection and the client will detect the missing ending chunk
		// and consider this an error
		//
		// this is the way to force close a request without logging the panic
		panic(http.ErrAbortHandler)
	}
}

type ImportHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewImportHandler(logger *zap.Logger, ah *action.ActionHandler) *ImportHandler {
	return &ImportHandler{log: logger.Sugar(), ah: ah}
}

func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.ah.Import(ctx, r.Body)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := httpResponse(w, http.StatusOK, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}

}
