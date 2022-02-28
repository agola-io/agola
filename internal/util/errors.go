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

package util

import (
	"errors"
	"fmt"
	"strings"
)

// Errors is an error that contains multiple errors
type Errors struct {
	Errs []error
}

func (e *Errors) IsErr() bool {
	return len(e.Errs) > 0
}

func (e *Errors) Append(err error) {
	e.Errs = append(e.Errs, err)
}

func (e *Errors) Error() string {
	errs := []string{}
	for _, err := range e.Errs {
		errs = append(errs, err.Error())
	}
	return strings.Join(errs, ", ")
}

func (e *Errors) Equal(e2 error) bool {
	errs1 := []string{}
	errs2 := []string{}
	for _, err := range e.Errs {
		errs1 = append(errs1, err.Error())
	}
	var es2 *Errors
	if errors.As(e2, &es2) {
		for _, err := range es2.Errs {
			errs2 = append(errs2, err.Error())
		}
	} else {
		errs2 = append(errs2, e2.Error())
	}

	return CompareStringSliceNoOrder(errs1, errs2)
}

type ErrorKind int
type ErrorCode string

const (
	ErrBadRequest ErrorKind = iota
	ErrNotExist
	ErrForbidden
	ErrUnauthorized
	ErrInternal
)

func (k ErrorKind) String() string {
	switch k {
	case ErrBadRequest:
		return "badrequest"
	case ErrNotExist:
		return "notexist"
	case ErrForbidden:
		return "forbidden"
	case ErrUnauthorized:
		return "unauthorized"
	case ErrInternal:
		return "internal"
	}

	return "unknown"
}

type APIError struct {
	err     error
	Kind    ErrorKind
	Code    ErrorCode
	Message string
}

func NewAPIError(kind ErrorKind, err error, options ...APIErrorOption) error {
	derr := &APIError{err: err, Kind: kind}

	for _, opt := range options {
		opt(derr)
	}

	return derr
}

func (e *APIError) Error() string {
	return e.err.Error()
}

func (e *APIError) Unwrap() error {
	return e.err
}

type APIErrorOption func(e *APIError)

func WithCode(code ErrorCode) APIErrorOption {
	return func(e *APIError) {
		e.Code = code
	}
}

func WithMessage(message string) APIErrorOption {
	return func(e *APIError) {
		e.Message = message
	}
}

func AsAPIError(err error) (*APIError, bool) {
	var derr *APIError
	return derr, errors.As(err, &derr)
}

func APIErrorIs(err error, kind ErrorKind) bool {
	if derr, ok := AsAPIError(err); ok && derr.Kind == kind {
		return true
	}

	return false
}

// RemoteError is an error received from a remote call. It's similar to
// APIError but with another type so it can be distinguished and won't be
// propagated to the api response.
type RemoteError struct {
	Kind    ErrorKind
	Code    string
	Message string
}

func NewRemoteError(kind ErrorKind, code string, message string) error {
	return &RemoteError{Kind: kind, Code: code, Message: message}
}

func (e *RemoteError) Error() string {
	code := e.Code
	message := e.Message
	errStr := fmt.Sprintf("remote error %s", e.Kind)
	if code != "" {
		errStr += fmt.Sprintf(" (code: %s)", code)
	}
	if message != "" {
		errStr += fmt.Sprintf(" (message: %s)", message)
	}

	return errStr
}

func AsRemoteError(err error) (*RemoteError, bool) {
	var rerr *RemoteError
	return rerr, errors.As(err, &rerr)
}

func RemoteErrorIs(err error, kind ErrorKind) bool {
	if rerr, ok := AsRemoteError(err); ok && rerr.Kind == kind {
		return true
	}

	return false
}

func KindFromRemoteError(err error) ErrorKind {
	if rerr, ok := AsRemoteError(err); ok {
		return rerr.Kind
	}

	return ErrInternal
}
