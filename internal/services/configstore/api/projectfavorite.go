// Copyright 2024 Sorint.lab
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

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

type CreateUserProjectFavoriteHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserProjectFavoriteHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserProjectFavoriteHandler {
	return &CreateUserProjectFavoriteHandler{log: log, ah: ah}
}

func (h *CreateUserProjectFavoriteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	userRef, err := url.PathUnescape(vars["userref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUserProjectFavoriteRequest{
		UserRef:    userRef,
		ProjectRef: projectRef,
	}

	userProjectFavorite, err := h.ah.CreateUserProjectFavorite(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, userProjectFavorite); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteUserProjectFavoriteHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserProjectFavoriteHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserProjectFavoriteHandler {
	return &DeleteUserProjectFavoriteHandler{log: log, ah: ah}
}

func (h *DeleteUserProjectFavoriteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	userRef, err := url.PathUnescape(vars["userref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	projectRef, err := url.PathUnescape(vars["projectref"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	err = h.ah.DeleteUserProjectFavorite(ctx, userRef, projectRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type UserProjectFavoritesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserProjectFavoritesHandler(log zerolog.Logger, ah *action.ActionHandler) *UserProjectFavoritesHandler {
	return &UserProjectFavoritesHandler{log: log, ah: ah}
}

func (h *UserProjectFavoritesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserProjectFavoritesHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.UserProjectFavorite, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	userRef, err := url.PathUnescape(vars["userref"])
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, err)
	}

	startUserProjectFavoriteID := query.Get("startuserprojectfavoriteid")

	ares, err := h.ah.GetUserProjectFavorites(ctx, &action.GetUserProjectFavoritesRequest{UserRef: userRef, StartUserProjectFavoriteID: startUserProjectFavoriteID, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	addHasMoreHeader(w, ares.HasMore)

	return ares.UserProjectFavorites, nil
}
