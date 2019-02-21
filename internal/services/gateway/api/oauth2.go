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
	"encoding/json"
	"net/http"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"

	"go.uber.org/zap"
)

type OAuth2CallbackHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
}

type RemoteSourceAuthResult struct {
	RequestType string      `json:"request_type,omitempty"`
	Response    interface{} `json:"response,omitempty"`
}

func NewOAuth2CallbackHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client) *OAuth2CallbackHandler {
	return &OAuth2CallbackHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient}
}

func (h *OAuth2CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	cresp, err := h.ch.HandleOauth2Callback(ctx, code, state)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var response interface{}
	switch cresp.RequestType {
	case "createuserla":
		authresp := cresp.Response.(*command.CreateUserLAResponse)
		response = &CreateUserLAResponse{
			LinkedAccount: authresp.LinkedAccount,
		}

	case "loginuser":
		authresp := cresp.Response.(*command.LoginUserResponse)
		response = &LoginUserResponse{
			Token: authresp.Token,
			User:  createUserResponse(authresp.User),
		}
	}

	resp := RemoteSourceAuthResult{
		RequestType: cresp.RequestType,
		Response:    response,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
