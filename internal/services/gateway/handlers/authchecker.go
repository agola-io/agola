// Copyright 2022 Sorint.lab
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
	"context"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
)

type SkipCSRFOnTokenAuth struct {
	log  zerolog.Logger
	next http.Handler
}

func NewSkipCSRFOnTokenAuth(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return &SkipCSRFOnTokenAuth{log, h}
	}
}

func (h *SkipCSRFOnTokenAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// skip csrf test if the request was a successful token auth
	ctx := r.Context()
	tokenAuth := ctx.Value(common.ContextKeyTokenAuth)
	if tokenAuth != nil && tokenAuth.(bool) {
		r = csrf.UnsafeSkipCheck(r)
	}

	h.next.ServeHTTP(w, r)
}

type SetCSRFHeader struct {
	log  zerolog.Logger
	next http.Handler
}

func NewSetCSRFHeader(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return &SetCSRFHeader{log, h}
	}
}

func (h *SetCSRFHeader) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Csrf-Token", csrf.Token(r))

	h.next.ServeHTTP(w, r)
}

type checkerResponse struct {
	ctxValues map[interface{}]interface{}
	cookies   []*http.Cookie

	// authErr is the auth error. Checkers should populate this instead of returning an error when it's a checker error and not an internal error
	// when authErr is nil the authentication was successful
	// when authErr is not nil the authentication will continue with other checkers (unless failAuth is true)
	authErr error

	// failAuth will fail the authentication without continuing with other checkers
	failAuth bool
}

type checker interface {
	Name() string

	DoAuth(context.Context, *http.Request) (*checkerResponse, error)
}

type AuthChecker struct {
	log               zerolog.Logger
	configstoreClient *csclient.Client

	next http.Handler

	required bool

	checkers []checker
}

type AuthCheckerOption func(*AuthChecker)

func WithRequired(required bool) AuthCheckerOption {
	return func(c *AuthChecker) {
		c.required = required
	}
}

func WithTokenChecker(adminToken string) AuthCheckerOption {
	return func(c *AuthChecker) {
		checker := &tokenChecker{
			log:               c.log,
			configstoreClient: c.configstoreClient,
			adminToken:        adminToken,
		}

		c.checkers = append(c.checkers, checker)
	}
}

func WithCookieChecker(sc *scommon.CookieSigningData, unsecureCookies bool) AuthCheckerOption {
	return func(c *AuthChecker) {
		checker := &cookieChecker{
			log:               c.log,
			configstoreClient: c.configstoreClient,
			sc:                sc,
			unsecureCookies:   unsecureCookies,
		}

		c.checkers = append(c.checkers, checker)
	}
}

func NewAuthChecker(log zerolog.Logger, configstoreClient *csclient.Client, opts ...AuthCheckerOption) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		c := &AuthChecker{
			log:               log,
			configstoreClient: configstoreClient,
			next:              h,
		}

		for _, option := range opts {
			option(c)
		}

		return c
	}
}

func (h *AuthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.do(ctx, w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
}

func (h *AuthChecker) do(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	for _, checker := range h.checkers {
		res, err := checker.DoAuth(ctx, r)
		if err != nil {
			return errors.WithStack(err)
		}

		hasAuth, err := h.checkAuthResponse(checker.Name(), res)
		if err != nil {
			return errors.WithStack(err)
		}

		if hasAuth {
			for key, value := range res.ctxValues {
				ctx = context.WithValue(ctx, key, value)
			}

			for _, cookie := range res.cookies {
				http.SetCookie(w, cookie)
			}

			h.doNext(ctx, w, r)
			return nil
		}
	}

	if h.required {
		return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("auth required but no auth data"))
	}

	h.doNext(ctx, w, r)
	return nil
}

func (h *AuthChecker) checkAuthResponse(name string, res *checkerResponse) (bool, error) {
	var hasAuth bool

	if res.failAuth {
		if res.authErr != nil {
			return false, util.NewAPIError(util.ErrUnauthorized, errors.Wrapf(res.authErr, "checker %s: auth failed", name))
		}
		return false, util.NewAPIError(util.ErrUnauthorized, errors.Errorf("checker %s: auth failed (no auth err reported by checker)", name))
	}

	if res.authErr != nil {
		h.log.Trace().Err(res.authErr).Msgf("checker %s: auth err: %+v", name, res.authErr)
	} else {
		hasAuth = true
	}

	return hasAuth, nil
}

func (h *AuthChecker) doNext(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	h.next.ServeHTTP(w, r.WithContext(ctx))
}

type tokenChecker struct {
	log zerolog.Logger

	configstoreClient *csclient.Client

	adminToken string
}

func (c *tokenChecker) Name() string { return "token" }

func (c *tokenChecker) DoAuth(ctx context.Context, r *http.Request) (*checkerResponse, error) {
	tokenString := common.ExtractToken(r.Header, "Authorization", "Token")
	if tokenString == "" {
		return &checkerResponse{authErr: errors.Errorf("no token provided")}, nil
	}

	if c.adminToken != "" {
		if tokenString == c.adminToken {
			ctxValues := map[interface{}]interface{}{
				common.ContextKeyTokenAuth: true,
				common.ContextKeyUserAdmin: true,
			}
			return &checkerResponse{ctxValues: ctxValues}, nil
		}
	}
	user, _, err := c.configstoreClient.GetUserByToken(ctx, tokenString)
	if err != nil {
		if util.RemoteErrorIs(err, util.ErrNotExist) {
			return &checkerResponse{authErr: errors.Errorf("user for token doesn't exist"), failAuth: true}, nil
		}
		return nil, errors.WithStack(err)
	}

	ctxValues := map[interface{}]interface{}{
		common.ContextKeyTokenAuth: true,
		common.ContextKeyUserID:    user.ID,
		common.ContextKeyUsername:  user.Name,
	}

	if user.Admin {
		ctxValues[common.ContextKeyUserAdmin] = true
	}

	return &checkerResponse{ctxValues: ctxValues}, nil
}

type cookieChecker struct {
	log zerolog.Logger

	configstoreClient *csclient.Client

	sc *scommon.CookieSigningData

	unsecureCookies bool
}

func (c *cookieChecker) Name() string { return "cookie" }

func (c *cookieChecker) DoAuth(ctx context.Context, r *http.Request) (*checkerResponse, error) {
	cookieName := common.AuthCookieName(c.unsecureCookies)
	cookie, err := r.Cookie(cookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(err)
	}

	secondaryCookieName := common.SecondaryAuthCookieName()
	secondaryCookie, err := r.Cookie(secondaryCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return nil, errors.WithStack(err)
	}

	var userID string
	var cookieValue common.AuthCookie

	if cookie == nil {
		return &checkerResponse{authErr: errors.Errorf("missing primary cookie")}, nil
	}
	if secondaryCookie == nil {
		return &checkerResponse{authErr: errors.Errorf("missing secondary cookie")}, nil
	}

	if err = c.sc.SecureCookie.Decode(cookieName, cookie.Value, &cookieValue); err != nil {
		return &checkerResponse{authErr: errors.Errorf("failed to decode cookie")}, nil
	}
	userID = cookieValue.Sub

	if userID == "" {
		return &checkerResponse{authErr: errors.Errorf("empty cookie userID")}, nil
	}

	var secondaryCookieValue common.SecondaryAuthCookie
	if err = c.sc.SecureCookie.Decode(cookieName, cookie.Value, &secondaryCookieValue); err != nil {
		return &checkerResponse{authErr: errors.Errorf("failed to decode secondary cookie")}, nil
	}

	if secondaryCookieValue.SecondaryToken != cookieValue.SecondaryToken {
		return &checkerResponse{authErr: errors.Errorf("different secondary cookie token")}, nil
	}

	user, _, err := c.configstoreClient.GetUser(ctx, userID)
	if err != nil {
		if util.RemoteErrorIs(err, util.ErrNotExist) {
			return &checkerResponse{authErr: errors.Errorf("user doesn't exist"), failAuth: true}, nil
		}
		return nil, errors.WithStack(err)
	}

	ctxValues := map[interface{}]interface{}{}
	cookies := []*http.Cookie{}

	ctxValues[common.ContextKeyUserID] = user.ID
	ctxValues[common.ContextKeyUsername] = user.Name

	if user.Admin {
		ctxValues[common.ContextKeyUserAdmin] = true
	}

	// send renewed cookies N hours before expire to keep the cookie expiration near to the configured one
	if time.Since(cookieValue.Expires) > 1*time.Hour {
		// generate cookies
		cookie, secondaryCookie, err := common.GenerateAuthCookies(userID, c.sc, c.unsecureCookies)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		cookies = append(cookies, cookie)
		cookies = append(cookies, secondaryCookie)
	}

	return &checkerResponse{ctxValues: ctxValues, cookies: cookies}, nil
}
