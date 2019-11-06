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
	"os"
	"path"
	"path/filepath"
	"strings"

	errors "golang.org/x/xerrors"
)

const (
	dataDirName = "data"
	tmpDirName  = "tmp"
)

type PosixStorage struct {
	dataDir string
	tmpDir  string
}

func NewPosix(baseDir string) (*PosixStorage, error) {
	if err := os.MkdirAll(baseDir, 0770); err != nil {
		return nil, err
	}
	dataDir := filepath.Join(baseDir, dataDirName)
	tmpDir := filepath.Join(baseDir, tmpDirName)
	if err := os.MkdirAll(dataDir, 0770); err != nil {
		return nil, errors.Errorf("failed to create data dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0770); err != nil {
		return nil, errors.Errorf("failed to create tmp dir: %w", err)
	}
	return &PosixStorage{
		dataDir: dataDir,
		tmpDir:  tmpDir,
	}, nil
}

func (s *PosixStorage) fsPath(p string) (string, error) {
	return filepath.Join(s.dataDir, p), nil
}

func (s *PosixStorage) Stat(p string) (*ObjectInfo, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(fspath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, NewErrNotExist(errors.Errorf("object %q doesn't exist", p))
		}
		return nil, err
	}

	return &ObjectInfo{Path: p, LastModified: fi.ModTime(), Size: fi.Size()}, nil
}

func (s *PosixStorage) ReadObject(p string) (ReadSeekCloser, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fspath)
	if err != nil && os.IsNotExist(err) {
		return nil, NewErrNotExist(errors.Errorf("object %q doesn't exist", p))
	}
	return f, err
}

func (s *PosixStorage) WriteObject(p string, data io.Reader, size int64, persist bool) error {
	fspath, err := s.fsPath(p)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(path.Dir(fspath), 0770); err != nil {
		return err
	}

	r := data
	if size >= 0 {
		r = io.LimitReader(data, size)
	}
	return writeFileAtomicFunc(fspath, s.dataDir, s.tmpDir, 0660, persist, func(f io.Writer) error {
		_, err := io.Copy(f, r)
		return err
	})
}

func (s *PosixStorage) DeleteObject(p string) error {
	fspath, err := s.fsPath(p)
	if err != nil {
		return err
	}

	if err := os.Remove(fspath); err != nil {
		if os.IsNotExist(err) {
			return NewErrNotExist(errors.Errorf("object %q doesn't exist", p))
		}
		return err
	}

	// try to remove parent empty dirs
	// TODO(sgotti) if this fails we ignore errors and the dirs will be left as
	// empty, clean them asynchronously
	pdir := filepath.Dir(fspath)
	for {
		if pdir == s.dataDir || !strings.HasPrefix(pdir, s.dataDir) {
			break
		}
		f, err := os.Open(pdir)
		if err != nil {
			return nil
		}

		_, err = f.Readdirnames(1)
		if err == io.EOF {
			f.Close()
			if err := os.Remove(pdir); err != nil {
				return nil
			}
		} else {
			f.Close()
			break
		}

		pdir = filepath.Dir(pdir)
	}
	return nil
}

func (s *PosixStorage) List(prefix, startWith, delimiter string, doneCh <-chan struct{}) <-chan ObjectInfo {
	objectCh := make(chan ObjectInfo, 1)

	if len(delimiter) > 1 {
		objectCh <- ObjectInfo{Err: errors.Errorf("wrong delimiter %q", delimiter)}
		return objectCh
	}

	if startWith != "" && !strings.Contains(startWith, prefix) {
		objectCh <- ObjectInfo{Err: errors.Errorf("wrong startwith value %q for prefix %q", startWith, prefix)}
		return objectCh
	}

	recursive := delimiter == ""

	// remove leading slash from prefix
	if strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}

	fprefix := filepath.Join(s.dataDir, prefix)
	root := filepath.Dir(fprefix)
	if len(root) < len(s.dataDir) {
		root = s.dataDir
	}

	// remove leading slash
	if strings.HasPrefix(startWith, "/") {
		startWith = strings.TrimPrefix(startWith, "/")
	}

	go func(objectCh chan<- ObjectInfo) {
		defer close(objectCh)
		err := filepath.Walk(root, func(ep string, info os.FileInfo, err error) error {
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if os.IsNotExist(err) {
				return nil
			}
			p := ep

			// get the path with / separator
			p = filepath.ToSlash(p)

			p, err = filepath.Rel(s.dataDir, p)
			if err != nil {
				return err
			}
			if !recursive && len(p) > len(prefix) {
				rel := strings.TrimPrefix(p, prefix)
				skip := strings.Contains(rel, delimiter)

				if info.IsDir() && skip {
					return filepath.SkipDir
				}
				if skip {
					return nil
				}
			}

			if info.IsDir() {
				return nil
			}

			if strings.HasPrefix(p, prefix) && p > startWith {
				select {
				// Send object content.
				case objectCh <- ObjectInfo{Path: p, LastModified: info.ModTime(), Size: info.Size()}:
				// If receives done from the caller, return here.
				case <-doneCh:
					return io.EOF
				}
			}

			return nil
		})
		if err != nil && err != io.EOF {
			objectCh <- ObjectInfo{
				Err: err,
			}
			return
		}
	}(objectCh)

	return objectCh
}
