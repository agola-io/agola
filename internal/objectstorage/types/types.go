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

package types

import (
	"errors"
	"io"
	"time"
)

// TODO(sgotti)
// define common errors (like notFound) so the implementations will return them
// instead of their own errors

var ErrNotExist = errors.New("does not exist")

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type ObjectInfo struct {
	Path string

	LastModified time.Time

	Err error
}
