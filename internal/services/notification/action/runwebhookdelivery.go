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

package action

import (
	"context"

	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
)

type GetProjectRunWebhookDeliveriesRequest struct {
	ProjectID            string
	DeliveryStatusFilter []types.DeliveryStatus

	StartSequence uint64

	Limit         int
	SortDirection types.SortDirection
}

type GetProjectRunWebhooksDeliveriesResponse struct {
	RunWebhookDeliveries []*types.RunWebhookDelivery

	HasMore bool
}

func (h *ActionHandler) GetProjectRunWebhookDeliveries(ctx context.Context, req *GetProjectRunWebhookDeliveriesRequest) (*GetProjectRunWebhooksDeliveriesResponse, error) {
	limit := req.Limit
	if limit > 0 {
		limit += 1
	}
	if req.SortDirection == "" {
		req.SortDirection = types.SortDirectionAsc
	}

	var runWebookDeliveries []*types.RunWebhookDelivery
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runWebookDeliveries, err = h.d.GetProjectRunWebhookDeliveriesAfterSequenceByProjectID(tx, req.StartSequence, req.ProjectID, req.DeliveryStatusFilter, limit, req.SortDirection)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var hasMore bool
	if req.Limit > 0 {
		hasMore = len(runWebookDeliveries) > req.Limit
		if hasMore {
			runWebookDeliveries = runWebookDeliveries[0:req.Limit]
		}
	}

	return &GetProjectRunWebhooksDeliveriesResponse{
		RunWebhookDeliveries: runWebookDeliveries,
		HasMore:              hasMore,
	}, nil
}

func (h *ActionHandler) RunWebhookRedelivery(ctx context.Context, projectID string, runWebhookDeliveryID string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runWebhookDelivery, err := h.d.GetRunWebhookDeliveryByID(tx, runWebhookDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}
		if runWebhookDelivery == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("runWebhookDelivery %q doesn't exist", runWebhookDeliveryID), serrors.RunWebhookDeliveryDoesNotExist())
		}

		runWebhook, err := h.d.GetRunWebhookByID(tx, runWebhookDelivery.RunWebhookID)
		if err != nil {
			return errors.WithStack(err)
		}
		if runWebhook == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("runWebhook %q doesn't exist", runWebhookDelivery.RunWebhookID), serrors.RunWebhookDoesNotExist())
		}
		if runWebhook.ProjectID != projectID {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("runWebhookDelivery %q doesn't belong to project %q", runWebhookDeliveryID, projectID), serrors.RunWebhookDeliveryDoesNotExist())
		}

		runWebhookDeliveries, err := h.d.GetRunWebhookDeliveriesByRunWebhookID(tx, runWebhookDelivery.RunWebhookID, []types.DeliveryStatus{types.DeliveryStatusNotDelivered}, 1, types.SortDirectionDesc)
		if err != nil {
			return errors.WithStack(err)
		}
		// check if runWebhook has delivery not delivered
		if len(runWebhookDeliveries) != 0 {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("the previous delivery of run webhook %q hasn't already been delivered", runWebhookDelivery.RunWebhookID), serrors.RunWebhookDeliveryAlreadyInProgress())
		}

		newRunWebhookDelivery := types.NewRunWebhookDelivery(tx)
		newRunWebhookDelivery.DeliveryStatus = types.DeliveryStatusNotDelivered
		newRunWebhookDelivery.RunWebhookID = runWebhookDelivery.RunWebhookID
		err = h.d.InsertRunWebhookDelivery(tx, newRunWebhookDelivery)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
