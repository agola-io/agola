package action

import (
	"context"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

type CreateUserProjectFavoriteRequest struct {
	UserRef    string
	ProjectRef string
}

func (h *ActionHandler) CreateUserProjectFavorite(ctx context.Context, req *CreateUserProjectFavoriteRequest) (*types.UserProjectFavorite, error) {
	var userProjectFavorite *types.UserProjectFavorite
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		user, err := h.d.GetUser(tx, req.UserRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if user == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user with ref %q doesn't exist", req.UserRef))
		}

		project, err := h.d.GetProject(tx, req.ProjectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q doesn't exist", req.ProjectRef))
		}

		// check duplicate user project favorite
		userProjectFavorite, err = h.d.GetUserProjectFavorite(tx, user.ID, project.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if userProjectFavorite != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user project favorite with user ref %q, project ref %q already exists", req.UserRef, req.ProjectRef))
		}

		userProjectFavorite = types.NewUserProjectFavorite(tx)
		userProjectFavorite.UserID = user.ID
		userProjectFavorite.ProjectID = project.ID

		if err := h.d.InsertUserProjectFavorite(tx, userProjectFavorite); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return userProjectFavorite, errors.WithStack(err)
}

func (h *ActionHandler) DeleteUserProjectFavorite(ctx context.Context, userRef, projectRef string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		user, err := h.d.GetUser(tx, userRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if user == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user with ref %q doesn't exist", userRef))
		}

		project, err := h.d.GetProject(tx, projectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q doesn't exist", projectRef))
		}

		// check project favorite existance
		userProjectFavorite, err := h.d.GetUserProjectFavorite(tx, user.ID, project.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if userProjectFavorite == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user project favorite for user %q, project %q doesn't exist", userRef, projectRef))
		}

		if err := h.d.DeleteUserProjectFavorite(tx, userProjectFavorite.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}

type GetUserProjectFavoritesRequest struct {
	UserRef string

	StartUserProjectFavoriteID string

	Limit         int
	SortDirection types.SortDirection
}

type GetUserProjectFavoritesResponse struct {
	UserProjectFavorites []*types.UserProjectFavorite

	HasMore bool
}

func (h *ActionHandler) GetUserProjectFavorites(ctx context.Context, req *GetUserProjectFavoritesRequest) (*GetUserProjectFavoritesResponse, error) {
	limit := req.Limit
	if limit > 0 {
		limit += 1
	}
	if req.SortDirection == "" {
		req.SortDirection = types.SortDirectionAsc
	}

	var userProjectFavorites []*types.UserProjectFavorite
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		user, err := h.d.GetUser(tx, req.UserRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if user == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user with ref %q doesn't exist", req.UserRef))
		}

		userProjectFavorites, err = h.d.GetUserProjectFavoritesByUserID(tx, user.ID, req.StartUserProjectFavoriteID, limit, req.SortDirection)
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
		hasMore = len(userProjectFavorites) > req.Limit
		if hasMore {
			userProjectFavorites = userProjectFavorites[0:req.Limit]
		}
	}

	return &GetUserProjectFavoritesResponse{
		UserProjectFavorites: userProjectFavorites,
		HasMore:              hasMore,
	}, nil
}
