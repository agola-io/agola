package common

import (
	"time"

	"github.com/gorilla/securecookie"
)

type CookieSigningData struct {
	Duration     time.Duration
	SecureCookie *securecookie.SecureCookie
}

type CookieSigningConfig struct {
	Duration time.Duration
	Key      string
}

func NewCookieSigningData(c *CookieSigningConfig) *CookieSigningData {
	sc := securecookie.New([]byte(c.Key), nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	// Set the MaxAge of the underlying securecookie.
	sc.MaxAge(int(c.Duration.Seconds()))

	return &CookieSigningData{Duration: c.Duration, SecureCookie: sc}
}
