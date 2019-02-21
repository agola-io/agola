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

func GenerateJWTToken(sd *TokenSigningData, remoteSourceName, requestType string, request interface{}) (string, error) {
	requestj, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(sd.Method, jwt.MapClaims{
		"exp":                time.Now().Add(sd.Duration).Unix(),
		"remote_source_name": remoteSourceName,
		"request_type":       requestType,
		"request":            string(requestj),
	})

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

func GenerateLoginJWTToken(sd *TokenSigningData, userID string) (string, error) {
	token := jwt.NewWithClaims(sd.Method, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(sd.Duration).Unix(),
	})

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
