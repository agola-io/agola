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
