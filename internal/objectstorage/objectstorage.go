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

type Storage interface {
	Stat(filepath string) (*ObjectInfo, error)
	ReadObject(filepath string) (ReadSeekCloser, error)
	WriteObject(filepath string, data io.Reader, size int64, persist bool) error
	DeleteObject(filepath string) error
	List(prefix, startWith, delimiter string, doneCh <-chan struct{}) <-chan ObjectInfo
}

type ObjectInfo struct {
	Path string

	LastModified time.Time

	Err error
}

// ObjStorage wraps a Storage providing additional helper functions
type ObjStorage struct {
	Storage
	delimiter string
}

func NewObjStorage(s Storage, delimiter string) *ObjStorage {
	return &ObjStorage{Storage: s, delimiter: delimiter}
}

func (s *ObjStorage) Delimiter() string {
	return s.delimiter
}

func (s *ObjStorage) List(prefix, startWith string, recursive bool, doneCh <-chan struct{}) <-chan ObjectInfo {
	delimiter := s.delimiter
	if recursive {
		delimiter = ""
	}

	return s.Storage.List(prefix, startWith, delimiter, doneCh)
}
