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
	"net/url"
	"strings"
)

const (
	etcdWalsMinRevisionRange = 100
)

type RefType int

const (
	RefTypeID RefType = iota
	RefTypePath
)

// ParseRef parses the api call to determine if the provided ref is
// an ID or a path
func ParseRef(projectRef string) (RefType, error) {
	projectRef, err := url.PathUnescape(projectRef)
	if err != nil {
		return -1, err
	}
	if strings.Contains(projectRef, "/") {
		return RefTypePath, nil
	}
	return RefTypeID, nil
}
