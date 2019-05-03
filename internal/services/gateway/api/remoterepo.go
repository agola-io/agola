// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"net/http"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
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
	ah                *action.ActionHandler
	configstoreClient *csapi.Client
}

func NewUserRemoteReposHandler(logger *zap.Logger, ah *action.ActionHandler, configstoreClient *csapi.Client) *UserRemoteReposHandler {
	return &UserRemoteReposHandler{log: logger.Sugar(), ah: ah, configstoreClient: configstoreClient}
}

func (h *UserRemoteReposHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	remoteSourceRef := vars["remotesourceref"]

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

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceRef)
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

	gitsource, err := h.ah.GetGitSource(ctx, rs, user.Name, la)
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
