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
	"github.com/sorintlab/errors"

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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *MaintenanceStatusHandler) do(r *http.Request) (*gwapitypes.MaintenanceStatusResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	ares, err := h.ah.IsMaintenanceEnabled(ctx, serviceName)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &gwapitypes.MaintenanceStatusResponse{RequestedStatus: ares.RequestedStatus, CurrentStatus: ares.CurrentStatus}

	return res, nil
}

type MaintenanceModeHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewMaintenanceModeHandler(log zerolog.Logger, ah *action.ActionHandler) *MaintenanceModeHandler {
	return &MaintenanceModeHandler{log: log, ah: ah}
}

func (h *MaintenanceModeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *MaintenanceModeHandler) do(r *http.Request) error {
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
		return errors.WithStack(err)
	}

	return nil
}

type ExportHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExportHandler(log zerolog.Logger, ah *action.ActionHandler) *ExportHandler {
	return &ExportHandler{log: log, ah: ah}
}

func (h *ExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ExportHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	resp, err := h.ah.Export(ctx, serviceName)
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		h.log.Err(err).Send()
		// since we already answered with a 200 we cannot return another error code
		// So abort the connection and the client will detect the missing ending chunk
		// and consider this an error
		//
		// this is the way to force close a request without logging the panic
		panic(http.ErrAbortHandler)
	}

	return nil
}

type ImportHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewImportHandler(log zerolog.Logger, ah *action.ActionHandler) *ImportHandler {
	return &ImportHandler{log: log, ah: ah}
}

func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ImportHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	serviceName := vars["servicename"]

	err := h.ah.Import(ctx, r.Body, serviceName)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
