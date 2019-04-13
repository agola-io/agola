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
	"bytes"
	"io"
)

type LimitedBuffer struct {
	*bytes.Buffer
	cap int
}

func (b *LimitedBuffer) Write(p []byte) (n int, err error) {
	if len(p)+b.Len() > b.cap {
		return 0, io.EOF
	}
	return b.Buffer.Write(p)
}

func NewLimitedBuffer(cap int) *LimitedBuffer {
	return &LimitedBuffer{Buffer: &bytes.Buffer{}, cap: cap}
}
