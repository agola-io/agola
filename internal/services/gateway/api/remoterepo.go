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

package api

import (
	"net/http"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	errors "golang.org/x/xerrors"
)

func createRemoteRepoResponse(r *gitsource.RepoInfo) *gwapitypes.RemoteRepoResponse {
	rr := &gwapitypes.RemoteRepoResponse{
		ID:   r.ID,
		Path: r.Path,
	}

	return rr
}

type UserRemoteReposHandler struct {
	log               zerolog.Logger
	ah                *action.ActionHandler
	configstoreClient *csclient.Client
}

func NewUserRemoteReposHandler(log zerolog.Logger, ah *action.ActionHandler, configstoreClient *csclient.Client) *UserRemoteReposHandler {
	return &UserRemoteReposHandler{log: log, ah: ah, configstoreClient: configstoreClient}
}

func (h *UserRemoteReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	remoteSourceRef := vars["remotesourceref"]

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user not authenticated")))
		return
	}

	user, _, err := h.configstoreClient.GetUser(ctx, userID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la == nil {
		err := util.NewAPIError(util.ErrBadRequest, errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name))
		util.HTTPError(w, err)
		h.log.Err(err).Send()
		return
	}

	gitsource, err := h.ah.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		util.HTTPError(w, err)
		h.log.Err(err).Send()
		return
	}

	remoteRepos, err := gitsource.ListUserRepos()
	if err != nil {
		err := util.NewAPIError(util.ErrBadRequest, errors.Errorf("failed to get user repositories from git source: %w", err))
		util.HTTPError(w, err)
		h.log.Err(err).Send()
		return
	}

	repos := make([]*gwapitypes.RemoteRepoResponse, len(remoteRepos))
	for i, r := range remoteRepos {
		repos[i] = createRemoteRepoResponse(r)
	}
	if err := util.HTTPResponse(w, http.StatusOK, repos); err != nil {
		h.log.Err(err).Send()
	}
}
