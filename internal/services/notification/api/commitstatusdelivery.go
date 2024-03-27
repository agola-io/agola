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

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/notification/action"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
)

const (
	DefaultCommitStatusDeliveriesLimit = 10
	MaxCommitStatusDeliveriesLimit     = 20
)

type CommitStatusDeliveriesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCommitStatusDeliveriesHandler(log zerolog.Logger, ah *action.ActionHandler) *CommitStatusDeliveriesHandler {
	return &CommitStatusDeliveriesHandler{log: log, ah: ah}
}

func (h *CommitStatusDeliveriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CommitStatusDeliveriesHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.CommitStatusDelivery, error) {
	ctx := r.Context()
	query := r.URL.Query()

	vars := mux.Vars(r)
	projectID := vars["projectid"]

	deliveryStatusFilter, err := types.DeliveryStatusFromStringSlice(query["deliverystatus"])
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("wrong deliverystatus"), serrors.InvalidDeliveryStatus())
	}

	startSequenceStr := query.Get("startsequence")
	var startSequence uint64
	if startSequenceStr != "" {
		var err error
		startSequence, err = strconv.ParseUint(startSequenceStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse startsequence"), serrors.InvalidStartSequence())
		}
	}

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ares, err := h.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: projectID, StartSequence: startSequence, DeliveryStatusFilter: deliveryStatusFilter, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	addHasMoreHeader(w, ares.HasMore)

	return ares.CommitStatusDeliveries, nil
}

type CommitStatusRedeliveryHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCommitStatusRedeliveryHandler(log zerolog.Logger, ah *action.ActionHandler) *CommitStatusRedeliveryHandler {
	return &CommitStatusRedeliveryHandler{log: log, ah: ah}
}

func (h *CommitStatusRedeliveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *CommitStatusRedeliveryHandler) do(r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectID := vars["projectid"]
	commitStatusDeliveryID := vars["commitstatusdeliveryid"]

	err := h.ah.CommitStatusRedelivery(ctx, projectID, commitStatusDeliveryID)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
