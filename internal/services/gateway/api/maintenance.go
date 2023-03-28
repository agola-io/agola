// Copyright 2022 Sorint.lab
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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

type MaintenanceStatusHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewMaintenanceStatusHandler(log zerolog.Logger, ah *action.ActionHandler) *MaintenanceStatusHandler {
	return &MaintenanceStatusHandler{log: log, ah: ah}
}

func (h *MaintenanceStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	ares, err := h.ah.IsMaintenanceEnabled(ctx, serviceName)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	resp := gwapitypes.MaintenanceStatusResponse{RequestedStatus: ares.RequestedStatus, CurrentStatus: ares.CurrentStatus}
	if err := util.HTTPResponse(w, http.StatusOK, resp); err != nil {
		h.log.Err(err).Send()
	}
}

type MaintenanceModeHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewMaintenanceModeHandler(log zerolog.Logger, ah *action.ActionHandler) *MaintenanceModeHandler {
	return &MaintenanceModeHandler{log: log, ah: ah}
}

func (h *MaintenanceModeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	enable := false
	switch r.Method {
	case "PUT":
		enable = true
	case "DELETE":
		enable = false
	}

	err := h.ah.MaintenanceMode(ctx, serviceName, enable)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type ExportHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExportHandler(log zerolog.Logger, ah *action.ActionHandler) *ExportHandler {
	return &ExportHandler{log: log, ah: ah}
}

func (h *ExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	resp, err := h.ah.Export(ctx, serviceName)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}
	defer resp.Body.Close()

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		h.log.Err(err).Send()
		panic(http.ErrAbortHandler)
	}
}

type ImportHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewImportHandler(log zerolog.Logger, ah *action.ActionHandler) *ImportHandler {
	return &ImportHandler{log: log, ah: ah}
}

func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	err := h.ah.Import(ctx, r.Body, serviceName)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}

}
