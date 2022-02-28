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
	"bytes"
	"io"

	"agola.io/agola/internal/errors"
)

type LimitedBuffer struct {
	*bytes.Buffer
	cap int
}

func (b *LimitedBuffer) Write(p []byte) (int, error) {
	if len(p)+b.Len() > b.cap {
		return 0, io.EOF
	}
	n, err := b.Buffer.Write(p)

	return n, errors.WithStack(err)
}

func NewLimitedBuffer(cap int) *LimitedBuffer {
	return &LimitedBuffer{Buffer: &bytes.Buffer{}, cap: cap}
}
