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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	util "agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	nstypes "agola.io/agola/services/notification/types"
)

func createRunWebhookDeliveryResponse(r *nstypes.RunWebhookDelivery) *gwapitypes.RunWebhookDeliveryResponse {
	runWebhookDelivery := &gwapitypes.RunWebhookDeliveryResponse{
		ID:             r.ID,
		Sequence:       r.Sequence,
		DeliveryStatus: gwapitypes.DeliveryStatus(r.DeliveryStatus),
		DeliveredAt:    r.DeliveredAt,
		StatusCode:     r.StatusCode,
	}
	return runWebhookDelivery
}

type ProjectRunWebhookDeliveries struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectRunWebhookDeliveriesHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectRunWebhookDeliveries {
	return &ProjectRunWebhookDeliveries{log: log, ah: ah}
}

func (h *ProjectRunWebhookDeliveries) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectRunWebhookDeliveries) do(w http.ResponseWriter, r *http.Request) ([]*gwapitypes.RunWebhookDeliveryResponse, error) {
	ctx := r.Context()
	query := r.URL.Query()

	vars := mux.Vars(r)
	projectRef := vars["projectref"]

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	deliveryStatusFilter := query["deliverystatus"]

	if ropts.Cursor != "" && len(deliveryStatusFilter) > 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("only one of cursor or deliverystatus should be provided"))
	}

	areq := &action.GetProjectRunWebhookDeliveriesRequest{
		ProjectRef: projectRef,

		DeliveryStatusFilter: deliveryStatusFilter,
		Cursor:               ropts.Cursor,
		Limit:                ropts.Limit,
		SortDirection:        action.SortDirection(ropts.SortDirection),
	}
	ares, err := h.ah.GetProjectRunWebhookDeliveries(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	runWebhookDeliveries := make([]*gwapitypes.RunWebhookDeliveryResponse, len(ares.RunWebhookDeliveries))
	for i, r := range ares.RunWebhookDeliveries {
		runWebhookDeliveries[i] = createRunWebhookDeliveryResponse(r)
	}

	addCursorHeader(w, ares.Cursor)

	return runWebhookDeliveries, nil
}

type ProjectRunWebhookRedelivery struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectRunWebhookRedeliveryHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectRunWebhookRedelivery {
	return &ProjectRunWebhookRedelivery{log: log, ah: ah}
}

func (h *ProjectRunWebhookRedelivery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectRunWebhookRedelivery) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectRef := vars["projectref"]
	runWebhookDeliveryID := vars["runwebhookdeliveryid"]

	areq := &action.ProjectRunWebhookRedeliveryRequest{
		ProjectRef:           projectRef,
		RunWebhookDeliveryID: runWebhookDeliveryID,
	}
	err := h.ah.ProjectRunWebhookRedelivery(ctx, areq)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
