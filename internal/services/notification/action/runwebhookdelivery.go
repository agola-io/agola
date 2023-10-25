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

	"agola.io/agola/internal/sqlg/sql"
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
