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

package handlers

import (
	"context"
	"net/http"
	"strings"

	"agola.io/agola/internal/errors"
	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"

	"github.com/golang-jwt/jwt/v4"
	jwtrequest "github.com/golang-jwt/jwt/v4/request"
	"github.com/rs/zerolog"
)

type AuthHandler struct {
	log  zerolog.Logger
	next http.Handler

	configstoreClient *csclient.Client
	adminToken        string

	sd *scommon.TokenSigningData

	required bool
}

func NewAuthHandler(log zerolog.Logger, configstoreClient *csclient.Client, adminToken string, sd *scommon.TokenSigningData, required bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return &AuthHandler{
			log:               log,
			next:              h,
			configstoreClient: configstoreClient,
			adminToken:        adminToken,
			sd:                sd,
			required:          required,
		}
	}
}

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tokenString, _ := TokenExtractor.ExtractToken(r)
	if h.adminToken != "" && tokenString != "" {
		if tokenString == h.adminToken {
			ctx = context.WithValue(ctx, common.ContextKeyUserAdmin, true)
			h.next.ServeHTTP(w, r.WithContext(ctx))
			return
		} else {
			user, _, err := h.configstoreClient.GetUserByToken(ctx, tokenString)
			if err != nil {
				if util.RemoteErrorIs(err, util.ErrNotExist) {
					http.Error(w, "", http.StatusUnauthorized)
					return
				}
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			// pass userid to handlers via context
			ctx = context.WithValue(ctx, common.ContextKeyUserID, user.ID)
			ctx = context.WithValue(ctx, common.ContextKeyUsername, user.Name)

			if user.Admin {
				ctx = context.WithValue(ctx, common.ContextKeyUserAdmin, true)
			}

			h.next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
	}

	tokenString, _ = BearerTokenExtractor.ExtractToken(r)
	if tokenString != "" {
		token, err := jwtrequest.ParseFromRequest(r, jwtrequest.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			sd := h.sd
			if token.Method != sd.Method {
				return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			var key interface{}
			switch sd.Method {
			case jwt.SigningMethodRS256:
				key = sd.PrivateKey
			case jwt.SigningMethodHS256:
				key = sd.Key
			default:
				return nil, errors.Errorf("unsupported signing method %q", sd.Method.Alg())
			}
			return key, nil
		})
		if err != nil {
			h.log.Err(err).Send()
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		// Set username in the request context
		claims := token.Claims.(jwt.MapClaims)
		userID := claims["sub"].(string)

		user, _, err := h.configstoreClient.GetUser(ctx, userID)
		if err != nil {
			if util.RemoteErrorIs(err, util.ErrNotExist) {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		// pass userid and username to handlers via context
		ctx = context.WithValue(ctx, common.ContextKeyUserID, user.ID)
		ctx = context.WithValue(ctx, common.ContextKeyUsername, user.Name)

		if user.Admin {
			ctx = context.WithValue(ctx, common.ContextKeyUserAdmin, true)
		}

		h.next.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	if h.required {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	h.next.ServeHTTP(w, r.WithContext(ctx))
}

func stripPrefixFromTokenString(prefix string) func(tok string) (string, error) {
	return func(tok string) (string, error) {
		pl := len(prefix)
		if len(tok) > pl && strings.EqualFold(tok[0:pl+1], prefix+" ") {
			return tok[pl+1:], nil
		}
		return "", nil
	}
}

// TokenExtractor extracts a token in format "token THETOKEN" from Authorization
// header
// Uses PostExtractionFilter to strip "token " prefix from header
var TokenExtractor = &jwtrequest.PostExtractionFilter{
	Extractor: jwtrequest.MultiExtractor{
		jwtrequest.HeaderExtractor{"Authorization"},
		jwtrequest.ArgumentExtractor{"access_token"},
	},
	Filter: stripPrefixFromTokenString("token"),
}

// BearerTokenExtractor extracts a bearer token in format "bearer THETOKEN" from
// Authorization header
// Uses PostExtractionFilter to strip "Bearer " prefix from header
var BearerTokenExtractor = &jwtrequest.PostExtractionFilter{
	Extractor: jwtrequest.MultiExtractor{
		jwtrequest.HeaderExtractor{"Authorization"},
		jwtrequest.ArgumentExtractor{"access_token"},
	},
	Filter: stripPrefixFromTokenString("bearer"),
}
