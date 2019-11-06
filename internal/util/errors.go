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
	"strings"

	errors "golang.org/x/xerrors"
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
	if es2, ok := e2.(*Errors); ok {
		for _, err := range es2.Errs {
			errs2 = append(errs2, err.Error())
		}
	} else {
		errs2 = append(errs2, e2.Error())
	}

	return CompareStringSliceNoOrder(errs1, errs2)
}

// ErrBadRequest represent an error caused by a bad command request
// it's used to differentiate an internal error from an user error
type ErrBadRequest struct {
	Err error
}

func (e *ErrBadRequest) Error() string {
	return e.Err.Error()
}

func NewErrBadRequest(err error) *ErrBadRequest {
	return &ErrBadRequest{Err: err}
}

func (*ErrBadRequest) Is(err error) bool {
	_, ok := err.(*ErrBadRequest)
	return ok
}

func IsBadRequest(err error) bool {
	return errors.Is(err, &ErrBadRequest{})
}

// ErrNotExist represent a not exist error
// it's used to differentiate an internal error from an user error
type ErrNotExist struct {
	Err error
}

func (e *ErrNotExist) Error() string {
	return e.Err.Error()
}

func NewErrNotExist(err error) *ErrNotExist {
	return &ErrNotExist{Err: err}
}

func (*ErrNotExist) Is(err error) bool {
	_, ok := err.(*ErrNotExist)
	return ok
}

func IsNotExist(err error) bool {
	return errors.Is(err, &ErrNotExist{})
}

// ErrForbidden represent an error caused by an forbidden operation
// it's used to differentiate an internal error from an user error
type ErrForbidden struct {
	Err error
}

func (e *ErrForbidden) Error() string {
	return e.Err.Error()
}

func NewErrForbidden(err error) *ErrForbidden {
	return &ErrForbidden{Err: err}
}

func (*ErrForbidden) Is(err error) bool {
	_, ok := err.(*ErrForbidden)
	return ok
}

func IsForbidden(err error) bool {
	return errors.Is(err, &ErrForbidden{})
}

// ErrUnauthorized represent an error caused by an unauthorized request
// it's used to differentiate an internal error from an user error
type ErrUnauthorized struct {
	Err error
}

func (e *ErrUnauthorized) Error() string {
	return e.Err.Error()
}

func NewErrUnauthorized(err error) *ErrUnauthorized {
	return &ErrUnauthorized{Err: err}
}

func (*ErrUnauthorized) Is(err error) bool {
	_, ok := err.(*ErrUnauthorized)
	return ok
}

func IsUnauthorized(err error) bool {
	return errors.Is(err, &ErrUnauthorized{})
}

type ErrInternal struct {
	Err error
}

// ErrInternal represent an internal error that should be returned to the user
func (e *ErrInternal) Error() string {
	return e.Err.Error()
}

func NewErrInternal(err error) *ErrInternal {
	return &ErrInternal{Err: err}
}

func (*ErrInternal) Is(err error) bool {
	_, ok := err.(*ErrInternal)
	return ok
}

func IsInternal(err error) bool {
	return errors.Is(err, &ErrInternal{})
}
