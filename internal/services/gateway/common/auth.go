package common

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sorintlab/errors"

	scommon "agola.io/agola/internal/services/common"
)

type ContextKey int

const (
	ContextKeyUserID ContextKey = iota
	ContextKeyUsername
	ContextKeyUserAdmin

	ContextKeyTokenAuth
)

func CurrentUserID(ctx context.Context) string {
	userIDVal := ctx.Value(ContextKeyUserID)
	if userIDVal == nil {
		return ""
	}
	return userIDVal.(string)
}

func IsUserLogged(ctx context.Context) bool {
	return ctx.Value(ContextKeyUserID) != nil
}

func IsUserAdmin(ctx context.Context) bool {
	isAdmin := false
	isAdminVal := ctx.Value(ContextKeyUserAdmin)
	if isAdminVal != nil {
		isAdmin = isAdminVal.(bool)
	}
	return isAdmin
}

func IsUserLoggedOrAdmin(ctx context.Context) bool {
	return IsUserLogged(ctx) || IsUserAdmin(ctx)
}

func AuthCookieName(unsecure bool) string {
	if unsecure {
		return "session"
	} else {
		return "__Host-session"
	}
}

func SecondaryAuthCookieName() string {
	return "secondarysession"
}

func CSRFCookieName(unsecure bool) string {
	if unsecure {
		return "csrf"
	} else {
		return "__Host-csrf"
	}
}

type AuthCookie struct {
	Sub            string    `json:"sub"`
	SecondaryToken string    `json:"secondaryToken"`
	Expires        time.Time `json:"expires"`
}

type SecondaryAuthCookie struct {
	SecondaryToken string `json:"secondaryToken"`
}

func GenerateAuthCookies(userID string, sc *scommon.CookieSigningData, unsecureCookies bool) (*http.Cookie, *http.Cookie, error) {
	secondaryToken := uuid.Must(uuid.NewV4()).String()

	expire := time.Now().Add(sc.Duration)

	cookieValue := AuthCookie{
		Sub:            userID,
		SecondaryToken: secondaryToken,
		Expires:        expire,
	}

	secondaryCookieValue := SecondaryAuthCookie{
		SecondaryToken: secondaryToken,
	}

	cookieName := AuthCookieName(unsecureCookies)
	secondaryCookieName := SecondaryAuthCookieName()

	cookieValueEncoded, err := sc.SecureCookie.Encode(cookieName, cookieValue)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secondaryCookieValueEncoded, err := sc.SecureCookie.Encode(secondaryCookieName, secondaryCookieValue)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	cookie := &http.Cookie{
		HttpOnly: true,
		Secure:   !unsecureCookies,
		Path:     "/",
		Name:     cookieName,
		SameSite: http.SameSiteStrictMode,
		Value:    cookieValueEncoded,
		MaxAge:   int(sc.Duration.Seconds()),
	}

	secondaryCookie := &http.Cookie{
		Secure:   !unsecureCookies,
		Path:     "/",
		Name:     secondaryCookieName,
		SameSite: http.SameSiteStrictMode,
		Value:    secondaryCookieValueEncoded,
		MaxAge:   int(sc.Duration.Seconds()),
	}

	return cookie, secondaryCookie, nil
}

func ExtractToken(hdr http.Header, name, prefix string) string {
	key := http.CanonicalHeaderKey(name)
	v := strings.TrimSpace(hdr.Get(key))
	if v == "" {
		return ""
	}

	pl := len(prefix)
	if len(v) > pl && strings.EqualFold(v[0:pl+1], prefix+" ") {
		return v[pl+1:]
	}
	return ""
}
