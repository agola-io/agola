// Copyright 2023 Sorint.lab
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
	"strconv"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"agola.io/agola/internal/services/notification/action"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
)

const (
	DefaultRunWebhookDeliveriesLimit = 10
	MaxRunWebhookDeliveriesLimit     = 20
)

type RunWebhookDeliveriesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRunWebhookDeliveriesHandler(log zerolog.Logger, ah *action.ActionHandler) *RunWebhookDeliveriesHandler {
	return &RunWebhookDeliveriesHandler{log: log, ah: ah}
}

func (h *RunWebhookDeliveriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunWebhookDeliveriesHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.RunWebhookDelivery, error) {
	ctx := r.Context()
	query := r.URL.Query()

	vars := mux.Vars(r)
	projectID := vars["projectid"]

	deliveryStatusFilter, err := types.DeliveryStatusFromStringSlice(query["deliverystatus"])
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "wrong deliverystatus"))
	}

	startSequenceStr := query.Get("startsequence")
	var startSequence uint64
	if startSequenceStr != "" {
		var err error
		startSequence, err = strconv.ParseUint(startSequenceStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse startsequence"))
		}
	}

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ares, err := h.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: projectID, StartSequence: startSequence, DeliveryStatusFilter: deliveryStatusFilter, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	addHasMoreHeader(w, ares.HasMore)

	return ares.RunWebhookDeliveries, nil
}

type RunWebhookRedeliveryHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRunWebhookRedeliveryHandler(log zerolog.Logger, ah *action.ActionHandler) *RunWebhookRedeliveryHandler {
	return &RunWebhookRedeliveryHandler{log: log, ah: ah}
}

func (h *RunWebhookRedeliveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunWebhookRedeliveryHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectID := vars["projectid"]
	runWebhookDeliveryID := vars["runwebhookdeliveryid"]

	err := h.ah.RunWebhookRedelivery(ctx, projectID, runWebhookDeliveryID)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
