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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/util"

	"go.uber.org/zap"
)

type OAuth2CallbackHandler struct {
	log               *zap.SugaredLogger
	ah                *action.ActionHandler
	configstoreClient *csapi.Client
}

type RemoteSourceAuthResult struct {
	RequestType string      `json:"request_type,omitempty"`
	Response    interface{} `json:"response,omitempty"`
}

func NewOAuth2CallbackHandler(logger *zap.Logger, ah *action.ActionHandler, configstoreClient *csapi.Client) *OAuth2CallbackHandler {
	return &OAuth2CallbackHandler{log: logger.Sugar(), ah: ah, configstoreClient: configstoreClient}
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
		response = &CreateUserLAResponse{
			LinkedAccount: authresp.LinkedAccount,
		}

	case action.RemoteSourceRequestTypeLoginUser:
		authresp := cresp.Response.(*action.LoginUserResponse)
		response = &LoginUserResponse{
			Token: authresp.Token,
			User:  createUserResponse(authresp.User),
		}

	case action.RemoteSourceRequestTypeAuthorize:
		authresp := cresp.Response.(*action.AuthorizeResponse)
		response = &AuthorizeResponse{
			RemoteUserInfo:   authresp.RemoteUserInfo,
			RemoteSourceName: authresp.RemoteSourceName,
		}

	case action.RemoteSourceRequestTypeRegisterUser:
		response = &RegisterUserResponse{}
	}

	res := RemoteSourceAuthResult{
		RequestType: string(cresp.RequestType),
		Response:    response,
	}
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
