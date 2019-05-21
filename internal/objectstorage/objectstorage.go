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

package objectstorage

import (
	"io"

	"github.com/sorintlab/agola/internal/objectstorage/types"
)

type Storage interface {
	Stat(filepath string) (*types.ObjectInfo, error)
	ReadObject(filepath string) (types.ReadSeekCloser, error)
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
