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
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
)

type GetProjectCommitStatusDeliveriesRequest struct {
	ProjectID            string
	DeliveryStatusFilter []types.DeliveryStatus

	StartSequence uint64

	Limit         int
	SortDirection types.SortDirection
}

type GetProjectCommitStatusDeliveriesResponse struct {
	CommitStatusDeliveries []*types.CommitStatusDelivery

	HasMore bool
}

func (h *ActionHandler) GetProjectCommitStatusDeliveries(ctx context.Context, req *GetProjectCommitStatusDeliveriesRequest) (*GetProjectCommitStatusDeliveriesResponse, error) {
	limit := req.Limit
	if limit > 0 {
		limit += 1
	}
	if req.SortDirection == "" {
		req.SortDirection = types.SortDirectionAsc
	}

	var commitStatusDeliveries []*types.CommitStatusDelivery
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		commitStatusDeliveries, err = h.d.GetProjectCommitStatusDeliveriesAfterSequenceByProjectID(tx, req.StartSequence, req.ProjectID, req.DeliveryStatusFilter, limit, req.SortDirection)
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
		hasMore = len(commitStatusDeliveries) > req.Limit
		if hasMore {
			commitStatusDeliveries = commitStatusDeliveries[0:req.Limit]
		}
	}

	return &GetProjectCommitStatusDeliveriesResponse{
		CommitStatusDeliveries: commitStatusDeliveries,
		HasMore:                hasMore,
	}, nil
}

func (h *ActionHandler) CommitStatusRedelivery(ctx context.Context, projectID string, commitStatusDeliveryID string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		commitStatusDelivery, err := h.d.GetCommitStatusDeliveryByID(tx, commitStatusDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}
		if commitStatusDelivery == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("commitStatusDelivery %q doesn't exist", commitStatusDeliveryID))
		}

		commitStatus, err := h.d.GetCommitStatusByID(tx, commitStatusDelivery.CommitStatusID)
		if err != nil {
			return errors.WithStack(err)
		}
		if commitStatus == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("commitStatus %q doesn't exist", commitStatusDelivery.CommitStatusID))
		}
		if commitStatus.ProjectID != projectID {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("commitStatusDelivery %q doesn't belong to project %q", commitStatusDeliveryID, projectID))
		}

		commitStatusDeliveries, err := h.d.GetCommitStatusDeliveriesByCommitStatusID(tx, commitStatusDelivery.CommitStatusID, []types.DeliveryStatus{types.DeliveryStatusNotDelivered}, 1, types.SortDirectionDesc)
		if err != nil {
			return errors.WithStack(err)
		}
		// check if commitStatus has delivery not delivered
		if len(commitStatusDeliveries) != 0 {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("the previous delivery of commit status %q hasn't already been delivered", commitStatusDelivery.CommitStatusID))
		}

		newCommitStatusDelivery := types.NewCommitStatusDelivery(tx)
		newCommitStatusDelivery.DeliveryStatus = types.DeliveryStatusNotDelivered
		newCommitStatusDelivery.CommitStatusID = commitStatusDelivery.CommitStatusID
		err = h.d.InsertCommitStatusDelivery(tx, newCommitStatusDelivery)
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
