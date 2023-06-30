// Copyright 2023 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.
package handlers

import (
	"net/http"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
)

type InternalAuthChecker struct {
	log zerolog.Logger

	next http.Handler

	apiToken string
}

func NewInternalAuthChecker(log zerolog.Logger, apiToken string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return &InternalAuthChecker{
			log:      log,
			next:     h,
			apiToken: apiToken,
		}
	}
}

func (h *InternalAuthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
}

func (h *InternalAuthChecker) do(w http.ResponseWriter, r *http.Request) error {
	if h.apiToken != "" {
		tokenString := common.ExtractToken(r.Header, "Authorization", "Token")

		if tokenString == "" {
			return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("no api token provided"))
		}

		if tokenString != h.apiToken {
			return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("wrong api token"))
		}
	}

	h.next.ServeHTTP(w, r)

	return nil
}
