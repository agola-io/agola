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

package util

import (
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

// ErrNotFound represent a not found error
// it's used to differentiate an internal error from an user error
type ErrNotFound struct {
	Err error
}

func (e *ErrNotFound) Error() string {
	return e.Err.Error()
}

func NewErrNotFound(err error) *ErrNotFound {
	return &ErrNotFound{Err: err}
}

func (*ErrNotFound) Is(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
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
