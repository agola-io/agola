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

package objectstorage

import (
	"context"
	"io"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
)

type ObjStorage interface {
	Stat(ctx context.Context, filepath string) (*ObjectInfo, error)
	ReadObject(ctx context.Context, filepath string) (ReadSeekCloser, error)
	// WriteObject atomically writes an object. If size is greater or equal to
	// zero then only size bytes will be read from data and wrote. If size is
	// less than zero data will be wrote until EOF. When persist is true the
	// implementation must ensure that data is persisted to the underlying
	// storage.
	WriteObject(ctx context.Context, filepath string, data io.Reader, size int64, persist bool) error
	DeleteObject(ctx context.Context, filepath string) error
	List(ctx context.Context, prefix, startAfter string, recursive bool) <-chan ObjectInfo
}

type ErrNotExist struct {
	*util.WrapperError
}

func NewErrNotExist(err error, format string, args ...interface{}) error {
	return &ErrNotExist{
		util.NewWrapperError(err, util.WithWrapperErrorMsg(format, args...)),
	}
}

func IsNotExist(err error) bool {
	var e *ErrNotExist
	return errors.As(err, &e)
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type ObjectInfo struct {
	Path         string
	LastModified time.Time
	Size         int64

	Err error
}
