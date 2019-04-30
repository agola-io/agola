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

package handlers

import (
	"context"
	"net/http"
	"strings"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"

	jwt "github.com/dgrijalva/jwt-go"
	jwtrequest "github.com/dgrijalva/jwt-go/request"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type AuthHandler struct {
	log  *zap.SugaredLogger
	next http.Handler

	configstoreClient *csapi.Client
	adminToken        string

	sd *common.TokenSigningData

	required bool
}

func NewAuthHandler(logger *zap.Logger, configstoreClient *csapi.Client, adminToken string, sd *common.TokenSigningData, required bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return &AuthHandler{
			log:               logger.Sugar(),
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
			ctx = context.WithValue(ctx, "admin", true)
			h.next.ServeHTTP(w, r.WithContext(ctx))
			return
		} else {
			user, resp, err := h.configstoreClient.GetUserByToken(ctx, tokenString)
			if err != nil && resp.StatusCode == http.StatusNotFound {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			// pass userid to handlers via context
			ctx = context.WithValue(ctx, "userid", user.ID)
			ctx = context.WithValue(ctx, "username", user.Name)
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
			h.log.Errorf("err: %+v", err)
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

		user, resp, err := h.configstoreClient.GetUser(ctx, userID)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		// pass userid to handlers via context
		ctx = context.WithValue(ctx, "userid", user.ID)
		ctx = context.WithValue(ctx, "username", user.Name)
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
		if len(tok) > pl && strings.ToUpper(tok[0:pl+1]) == strings.ToUpper(prefix+" ") {
			return tok[pl+1:], nil
		}
		return "", nil
	}
}

// TokenExtractor extracts a token in format "token THETOKEN" from Authorization
// header
// Uses PostExtractionFilter to strip "token " prefix from header
var TokenExtractor = &jwtrequest.PostExtractionFilter{
	jwtrequest.MultiExtractor{
		jwtrequest.HeaderExtractor{"Authorization"},
		jwtrequest.ArgumentExtractor{"access_token"},
	},
	stripPrefixFromTokenString("token"),
}

// BearerTokenExtractor extracts a bearer token in format "bearer THETOKEN" from
// Authorization header
// Uses PostExtractionFilter to strip "Bearer " prefix from header
var BearerTokenExtractor = &jwtrequest.PostExtractionFilter{
	jwtrequest.MultiExtractor{
		jwtrequest.HeaderExtractor{"Authorization"},
		jwtrequest.ArgumentExtractor{"access_token"},
	},
	stripPrefixFromTokenString("bearer"),
}
