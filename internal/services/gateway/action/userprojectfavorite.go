// Copyright 2019 Sorint.lab
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

	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/client"
	cstypes "agola.io/agola/services/configstore/types"
)

type CreateUserProjectFavoriteRequest struct {
	ProjectRef string
}

func (h *ActionHandler) CreateUserProjectFavorite(ctx context.Context, req *CreateUserProjectFavoriteRequest) (*cstypes.UserProjectFavorite, error) {
	if !common.IsUserLogged(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	userID := common.CurrentUserID(ctx)

	creq := &csapitypes.CreateUserProjectFavoriteRequest{
		UserRef:    userID,
		ProjectRef: req.ProjectRef,
	}

	userProjectFavorite, _, err := h.configstoreClient.CreateUserProjectFavorite(ctx, creq)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to create user project favorite"))
	}

	return userProjectFavorite, nil
}

func (h *ActionHandler) DeleteUserProjectFavorite(ctx context.Context, projectRef string) error {
	if !common.IsUserLogged(ctx) {
		return errors.Errorf("user not logged in")
	}

	userID := common.CurrentUserID(ctx)

	if _, err := h.configstoreClient.DeleteUserProjectFavorite(ctx, userID, projectRef); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to delete user project favorite"))
	}
	return nil
}

type GetUserProjectFavoritesRequest struct {
	Cursor string

	Limit         int
	SortDirection SortDirection
}

type GetUserProjectFavoritesResponse struct {
	UserProjectFavorites []*cstypes.UserProjectFavorite
	Cursor               string
}

func (h *ActionHandler) GetUserProjectFavorites(ctx context.Context, req *GetUserProjectFavoritesRequest) (*GetUserProjectFavoritesResponse, error) {
	if !common.IsUserLogged(ctx) {
		return nil, errors.Errorf("user not logged in")
	}
	userID := common.CurrentUserID(ctx)

	inCursor := &StartCursor{}
	sortDirection := req.SortDirection
	if req.Cursor != "" {
		if err := UnmarshalCursor(req.Cursor, inCursor); err != nil {
			return nil, errors.WithStack(err)
		}
		sortDirection = inCursor.SortDirection
	}
	if sortDirection == "" {
		sortDirection = SortDirectionAsc
	}

	userProjectFavorites, resp, err := h.configstoreClient.GetUserProjectFavorites(ctx, userID, &client.GetUserProjectFavoritesOptions{ListOptions: &client.ListOptions{Limit: req.Limit, SortDirection: cstypes.SortDirection(sortDirection)}, StartUserProjectFavoriteID: inCursor.Start})
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	var outCursor string
	if resp.HasMore && len(userProjectFavorites) > 0 {
		lastuserProjectFavoriteID := userProjectFavorites[len(userProjectFavorites)-1].ID
		outCursor, err = MarshalCursor(&StartCursor{
			Start:         lastuserProjectFavoriteID,
			SortDirection: sortDirection,
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	res := &GetUserProjectFavoritesResponse{
		UserProjectFavorites: userProjectFavorites,
		Cursor:               outCursor,
	}

	return res, nil
}
