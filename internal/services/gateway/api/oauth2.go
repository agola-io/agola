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
