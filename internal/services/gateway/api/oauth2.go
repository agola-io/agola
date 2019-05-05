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

	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/util"

	"go.uber.org/zap"
)

type OAuth2CallbackHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

type RemoteSourceAuthResult struct {
	RequestType string      `json:"request_type,omitempty"`
	Response    interface{} `json:"response,omitempty"`
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
