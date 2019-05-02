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

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type RemoteRepoResponse struct {
	ID   string `json:"id,omitempty"`
	Path string `json:"path,omitempty"`
}

func createRemoteRepoResponse(r *gitsource.RepoInfo) *RemoteRepoResponse {
	rr := &RemoteRepoResponse{
		ID:   r.ID,
		Path: r.Path,
	}

	return rr
}

type UserRemoteReposHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
}

func NewUserRemoteReposHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client) *UserRemoteReposHandler {
	return &UserRemoteReposHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient}
}

func (h *UserRemoteReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	remoteSourceID := vars["remotesourceid"]

	userIDVal := ctx.Value("userid")
	if userIDVal == nil {
		httpError(w, util.NewErrBadRequest(errors.Errorf("user not authenticated")))
		return
	}
	userID := userIDVal.(string)
	h.log.Infof("userID: %q", userID)

	user, resp, err := h.configstoreClient.GetUser(ctx, userID)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceID)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}
	h.log.Infof("rs: %s", util.Dump(rs))

	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	h.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		httpError(w, util.NewErrBadRequest(errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name)))
		return
	}

	gitsource, err := h.ch.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "failed to create gitsource client")))
		return
	}

	remoteRepos, err := gitsource.ListUserRepos()
	if err != nil {
		httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "failed to get user repositories from gitsource")))
		return
	}

	repos := make([]*RemoteRepoResponse, len(remoteRepos))
	for i, r := range remoteRepos {
		repos[i] = createRemoteRepoResponse(r)
	}
	if err := httpResponse(w, http.StatusOK, repos); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
