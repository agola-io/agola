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

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"

	"go.uber.org/zap"
)

type OAuth2CallbackHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewOAuth2CallbackHandler(logger *zap.Logger, ah *action.ActionHandler) *OAuth2CallbackHandler {
	return &OAuth2CallbackHandler{log: logger.Sugar(), ah: ah}
}

func (h *OAuth2CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	cresp, err := h.ah.HandleOauth2Callback(ctx, code, state)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	var response interface{}
	switch cresp.RequestType {
	case action.RemoteSourceRequestTypeCreateUserLA:
		authresp := cresp.Response.(*action.CreateUserLAResponse)
		response = &gwapitypes.CreateUserLAResponse{
			LinkedAccount: &gwapitypes.LinkedAccount{
				ID:                  authresp.LinkedAccount.ID,
				RemoteUserID:        authresp.LinkedAccount.RemoteUserID,
				RemoteUserName:      authresp.LinkedAccount.RemoteUserName,
				RemoteUserAvatarURL: authresp.LinkedAccount.RemoteUserAvatarURL,
				RemoteSourceID:      authresp.LinkedAccount.RemoteUserID,
			},
		}

	case action.RemoteSourceRequestTypeLoginUser:
		authresp := cresp.Response.(*action.LoginUserResponse)
		response = &gwapitypes.LoginUserResponse{
			Token: authresp.Token,
			User:  createUserResponse(authresp.User),
		}

	case action.RemoteSourceRequestTypeAuthorize:
		authresp := cresp.Response.(*action.AuthorizeResponse)
		response = &gwapitypes.AuthorizeResponse{
			RemoteUserInfo: &gwapitypes.UserInfo{
				ID:        authresp.RemoteUserInfo.ID,
				LoginName: authresp.RemoteUserInfo.LoginName,
				Email:     authresp.RemoteUserInfo.Email,
			},
			RemoteSourceName: authresp.RemoteSourceName,
		}

	case action.RemoteSourceRequestTypeRegisterUser:
		response = &gwapitypes.RegisterUserResponse{}
	}

	res := gwapitypes.RemoteSourceAuthResult{
		RequestType: string(cresp.RequestType),
		Response:    response,
	}
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
