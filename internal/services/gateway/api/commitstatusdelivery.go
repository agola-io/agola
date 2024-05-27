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
	"net/url"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	util "agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	nstypes "agola.io/agola/services/notification/types"
)

func createCommitStatusDeliveryResponse(r *nstypes.CommitStatusDelivery) *gwapitypes.CommitStatusDeliveryResponse {
	commitStatusDelivery := &gwapitypes.CommitStatusDeliveryResponse{
		ID:             r.ID,
		Sequence:       r.Sequence,
		DeliveryStatus: gwapitypes.DeliveryStatus(r.DeliveryStatus),
		DeliveredAt:    r.DeliveredAt,
	}
	return commitStatusDelivery
}

type ProjectCommitStatusDeliveries struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectCommitStatusDeliveriesHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectCommitStatusDeliveries {
	return &ProjectCommitStatusDeliveries{log: log, ah: ah}
}

func (h *ProjectCommitStatusDeliveries) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ProjectCommitStatusDeliveries) do(w http.ResponseWriter, r *http.Request) ([]*gwapitypes.CommitStatusDeliveryResponse, error) {
	ctx := r.Context()
	query := r.URL.Query()

	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	deliveryStatusFilter := query["deliverystatus"]

	if ropts.Cursor != "" && len(deliveryStatusFilter) > 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("only one of cursor or deliverystatus should be provided"))
	}

	areq := &action.GetProjectCommitStatusDeliveriesRequest{
		ProjectRef: projectRef,

		DeliveryStatusFilter: deliveryStatusFilter,
		Cursor:               ropts.Cursor,
		Limit:                ropts.Limit,
		SortDirection:        action.SortDirection(ropts.SortDirection),
	}
	ares, err := h.ah.GetProjectCommitStatusDeliveries(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	commitStatusDeliveries := make([]*gwapitypes.CommitStatusDeliveryResponse, len(ares.CommitStatusDeliveries))
	for i, r := range ares.CommitStatusDeliveries {
		commitStatusDeliveries[i] = createCommitStatusDeliveryResponse(r)
	}

	addCursorHeader(w, ares.Cursor)

	return commitStatusDeliveries, nil
}

type ProjectCommitStatusRedelivery struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewProjectCommitStatusRedeliveryHandler(log zerolog.Logger, ah *action.ActionHandler) *ProjectCommitStatusRedelivery {
	return &ProjectCommitStatusRedelivery{log: log, ah: ah}
}

func (h *ProjectCommitStatusRedelivery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ProjectCommitStatusRedelivery) do(r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}
	commitStatusDeliveryID := vars["commitstatusdeliveryid"]

	areq := &action.ProjectCommitStatusRedeliveryRequest{
		ProjectRef:             projectRef,
		CommitStatusDeliveryID: commitStatusDeliveryID,
	}
	err = h.ah.ProjectCommitStatusRedelivery(ctx, areq)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
