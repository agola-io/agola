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

	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/client"
	nstypes "agola.io/agola/services/notification/types"
)

type GetProjectRunWebhookDeliveriesRequest struct {
	ProjectRef           string
	DeliveryStatusFilter []string

	Cursor string

	Limit         int
	SortDirection SortDirection
}

type GetProjectRunWebhookDeliveriesResponse struct {
	RunWebhookDeliveries []*nstypes.RunWebhookDelivery
	Cursor               string
}

func (h *ActionHandler) GetProjectRunWebhookDeliveries(ctx context.Context, req *GetProjectRunWebhookDeliveriesRequest) (*GetProjectRunWebhookDeliveriesResponse, error) {
	project, _, err := h.configstoreClient.GetProject(ctx, req.ProjectRef)
	if err != nil {
		return nil, APIErrorFromRemoteError(err)
	}
	isUserOwner, err := h.IsAuthUserProjectOwner(ctx, project.OwnerType, project.OwnerID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !isUserOwner {
		return nil, util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	inCursor := &DeliveryCursor{}
	sortDirection := req.SortDirection
	deliveryStatusFilter := req.DeliveryStatusFilter
	if req.Cursor != "" {
		if err := UnmarshalCursor(req.Cursor, inCursor); err != nil {
			return nil, errors.WithStack(err)
		}
		sortDirection = inCursor.SortDirection
		deliveryStatusFilter = inCursor.DeliveryStatusFilter
	}
	if sortDirection == "" {
		sortDirection = SortDirectionAsc
	}

	runWebhookDeliveries, resp, err := h.notificationClient.GetProjectRunWebhookDeliveries(ctx, project.ID, &client.GetProjectRunWebhookDeliveriesOptions{ListOptions: &client.ListOptions{Limit: req.Limit, SortDirection: nstypes.SortDirection(sortDirection)}, StartSequence: inCursor.StartSequence, DeliveryStatusFilter: deliveryStatusFilter})
	if err != nil {
		return nil, APIErrorFromRemoteError(err)
	}

	var outCursor string
	if resp.HasMore && len(runWebhookDeliveries) > 0 {
		lastRunWebhookDeliverySequence := runWebhookDeliveries[len(runWebhookDeliveries)-1].Sequence
		outCursor, err = MarshalCursor(&DeliveryCursor{
			StartSequence: lastRunWebhookDeliverySequence,
			SortDirection: sortDirection,

			DeliveryStatusFilter: deliveryStatusFilter,
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	res := &GetProjectRunWebhookDeliveriesResponse{
		RunWebhookDeliveries: runWebhookDeliveries,
		Cursor:               outCursor,
	}

	return res, nil
}

type ProjectRunWebhookRedeliveryRequest struct {
	ProjectRef           string
	RunWebhookDeliveryID string
}

func (h *ActionHandler) ProjectRunWebhookRedelivery(ctx context.Context, req *ProjectRunWebhookRedeliveryRequest) error {
	project, _, err := h.configstoreClient.GetProject(ctx, req.ProjectRef)
	if err != nil {
		return APIErrorFromRemoteError(err)
	}
	isUserOwner, err := h.IsAuthUserProjectOwner(ctx, project.OwnerType, project.OwnerID)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !isUserOwner {
		return util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	_, err = h.notificationClient.RunWebhookRedelivery(ctx, project.ID, req.RunWebhookDeliveryID)
	if err != nil {
		return APIErrorFromRemoteError(err)
	}

	return nil
}
