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
	"fmt"
	"strings"

	"github.com/sorintlab/errors"
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

	return EqualStringSliceNoOrder(errs1, errs2)
}

// Wrapper error is an helper error type that (optionally) wrap an error and add stack information starting at the frame where the error has been created
// It's meant to be embedded in custom errors to avoid the need to redefine the Error, Unwrap and StackTrace methods.
//
// Example usage:
//
//	type CustomError struct {
//		*WrapperError
//	}
//
//	func NewCustomError(err error) error {
//		return &CustomError{
//			util.NewWrapperError(err, util.WithWrapperErrorMsg("connection error")),
//		}
//	}
//
// Create the error
//
//	if err != nil {
//		return NewCustomError(err)
//	}
//
// Create the error without wrapping another error
//
//	return NewCustomError(nil)
//
// Detect error type
//
//	var werr *CustomError
//	if errors.As(err, &werr) {
//		fmt.Println("this is a CustomError")
//	}
type WrapperError struct {
	err error
	msg string

	stack *errors.Stack
}

func NewWrapperError(err error, options ...WrapperErrorOption) *WrapperError {
	werr := &WrapperError{err: err}

	for _, opt := range options {
		opt(werr)
	}

	if werr.stack == nil {
		// skip one frame by default if the error is used as in the example
		werr.stack = errors.Callers(1)
	}

	return werr
}

type WrapperErrorOption func(e *WrapperError)

func WithWrapperErrorMsg(format string, args ...interface{}) WrapperErrorOption {
	return func(e *WrapperError) {
		e.msg = fmt.Sprintf(format, args...)
	}
}

func WithWrapperErrorCallerDepth(depth int) WrapperErrorOption {
	return func(e *WrapperError) {
		e.stack = errors.Callers(depth + 1)
	}
}

func (w *WrapperError) Error() string {
	if w.err == nil {
		return w.msg
	}
	if w.msg != "" {
		return w.msg + ": " + w.err.Error()
	} else {
		return w.err.Error()
	}
}

func (w *WrapperError) Unwrap() error { return w.err }

func (w *WrapperError) StackTrace() errors.StackTrace {
	return w.stack.StackTrace()
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
	*WrapperError

	Kind    ErrorKind
	Code    ErrorCode
	Message string

	msg   string
	depth int
}

func NewAPIErrorWrap(kind ErrorKind, err error, options ...APIErrorOption) error {
	aerr := &APIError{Kind: kind, depth: 1}

	for _, opt := range options {
		opt(aerr)
	}

	aerr.WrapperError = NewWrapperError(err, WithWrapperErrorMsg(aerr.message()), WithWrapperErrorCallerDepth(aerr.depth))

	return aerr
}

func NewAPIError(kind ErrorKind, options ...APIErrorOption) error {
	aerr := &APIError{Kind: kind, depth: 1}

	for _, opt := range options {
		opt(aerr)
	}

	aerr.WrapperError = NewWrapperError(nil, WithWrapperErrorMsg(aerr.message()), WithWrapperErrorCallerDepth(aerr.depth))

	return aerr
}

func (e *APIError) message() string {
	msg := e.msg
	if msg != "" {
		msg += ", "
	}
	msg += fmt.Sprintf("apiError (kind: %s", e.Kind)
	if e.Code != "" {
		msg += fmt.Sprintf(", code: %s", e.Code)
	}
	if e.Message != "" {
		msg += fmt.Sprintf(", message: %s", e.Message)
	}
	msg += ")"

	return msg
}

type APIErrorOption func(e *APIError)

// WithAPIErrorMsg adds an internal message to the error. This message could
// contain sensitive data so it's just for internal logging and will not be sent
// to the api caller.
func WithAPIErrorMsg(format string, args ...interface{}) APIErrorOption {
	return func(e *APIError) {
		e.msg = fmt.Sprintf(format, args...)
	}
}

func WithAPIErrorCallerDepth(depth int) APIErrorOption {
	return func(e *APIError) {
		e.depth = depth
	}
}

func WithAPIErrorUserCode(code ErrorCode) APIErrorOption {
	return func(e *APIError) {
		e.Code = code
	}
}

func WithAPIErrorUserMessage(message string) APIErrorOption {
	return func(e *APIError) {
		e.Message = message
	}
}

func AsAPIError(err error) (*APIError, bool) {
	var aerr *APIError
	return aerr, errors.As(err, &aerr)
}

func APIErrorIs(err error, kind ErrorKind) bool {
	if aerr, ok := AsAPIError(err); ok && aerr.Kind == kind {
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
