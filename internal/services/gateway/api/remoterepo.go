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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	gwapitypes "agola.io/agola/services/gateway/api/types"
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserRemoteReposHandler) do(r *http.Request) ([]*gwapitypes.RemoteRepoResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	remoteSourceRef := vars["remotesourceref"]

	gitsource, _, _, err := h.ah.GetCurrentUserGitSource(ctx, remoteSourceRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteRepos, err := gitsource.ListUserRepos()
	if err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("failed to get user repositories from git source"))
	}

	repos := make([]*gwapitypes.RemoteRepoResponse, len(remoteRepos))
	for i, r := range remoteRepos {
		repos[i] = createRemoteRepoResponse(r)
	}

	return repos, nil
}
