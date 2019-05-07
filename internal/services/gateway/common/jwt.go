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

package common

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type TokenSigningData struct {
	Duration   time.Duration
	Method     jwt.SigningMethod
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Key        []byte
}

func GenerateGenericJWTToken(sd *TokenSigningData, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(sd.Method, claims)

	var key interface{}
	switch sd.Method {
	case jwt.SigningMethodRS256:
		key = sd.PrivateKey
	case jwt.SigningMethodHS256:
		key = sd.Key
	default:
		errors.Errorf("unsupported signing method %q", sd.Method.Alg())
	}
	// Sign and get the complete encoded token as a string
	return token.SignedString(key)
}

func GenerateOauth2JWTToken(sd *TokenSigningData, remoteSourceName, requestType string, request interface{}) (string, error) {
	requestj, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	return GenerateGenericJWTToken(sd, jwt.MapClaims{
		"exp":                time.Now().Add(sd.Duration).Unix(),
		"remote_source_name": remoteSourceName,
		"request_type":       requestType,
		"request":            string(requestj),
	})
}

func GenerateLoginJWTToken(sd *TokenSigningData, userID string) (string, error) {
	return GenerateGenericJWTToken(sd, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(sd.Duration).Unix(),
	})
}
