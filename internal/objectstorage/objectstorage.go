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
	"io"

	"agola.io/agola/internal/objectstorage/types"
)

type Storage interface {
	Stat(filepath string) (*types.ObjectInfo, error)
	ReadObject(filepath string) (types.ReadSeekCloser, error)
	// WriteObject atomically writes an object. If size is greater or equal to
	// zero then only size bytes will be read from data and wrote. If size is
	// less than zero data will be wrote until EOF. When persist is true the
	// implementation must ensure that data is persisted to the underlying
	// storage.
	WriteObject(filepath string, data io.Reader, size int64, persist bool) error
	DeleteObject(filepath string) error
	List(prefix, startWith, delimiter string, doneCh <-chan struct{}) <-chan types.ObjectInfo
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

func (s *ObjStorage) List(prefix, startWith string, recursive bool, doneCh <-chan struct{}) <-chan types.ObjectInfo {
	delimiter := s.delimiter
	if recursive {
		delimiter = ""
	}

	return s.Storage.List(prefix, startWith, delimiter, doneCh)
}
