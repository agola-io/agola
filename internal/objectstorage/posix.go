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
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
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
		return nil, errors.WithStack(err)
	}
	dataDir := filepath.Join(baseDir, dataDirName)
	tmpDir := filepath.Join(baseDir, tmpDirName)
	if err := os.MkdirAll(dataDir, 0770); err != nil {
		return nil, errors.Wrapf(err, "failed to create data dir")
	}
	if err := os.MkdirAll(tmpDir, 0770); err != nil {
		return nil, errors.Wrapf(err, "failed to create tmp dir")
	}
	return &PosixStorage{
		dataDir: dataDir,
		tmpDir:  tmpDir,
	}, nil
}

func (s *PosixStorage) fsPath(p string) (string, error) {
	return filepath.Join(s.dataDir, p), nil
}

func (s *PosixStorage) Stat(ctx context.Context, p string) (*ObjectInfo, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	fi, err := os.Stat(fspath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, NewErrNotExist(err, "object %q doesn't exist", p)
		}
		return nil, errors.WithStack(err)
	}

	return &ObjectInfo{Path: p, LastModified: fi.ModTime(), Size: fi.Size()}, nil
}

func (s *PosixStorage) ReadObject(ctx context.Context, p string) (ReadSeekCloser, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	f, err := os.Open(fspath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, NewErrNotExist(err, "object %q doesn't exist", p)
	}
	return f, errors.WithStack(err)
}

func (s *PosixStorage) WriteObject(ctx context.Context, p string, data io.Reader, size int64, persist bool) error {
	fspath, err := s.fsPath(p)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := os.MkdirAll(path.Dir(fspath), 0770); err != nil {
		return errors.WithStack(err)
	}

	r := data
	if size >= 0 {
		r = io.LimitReader(data, size)
	}
	return writeFileAtomicFunc(fspath, s.dataDir, s.tmpDir, 0660, persist, func(f io.Writer) error {
		_, err := io.Copy(f, r)
		return errors.WithStack(err)
	})
}

func (s *PosixStorage) DeleteObject(ctx context.Context, p string) error {
	fspath, err := s.fsPath(p)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := os.Remove(fspath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewErrNotExist(err, "object %q doesn't exist", p)
		}
		return errors.WithStack(err)
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
		if errors.Is(err, io.EOF) {
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

func (s *PosixStorage) List(ctx context.Context, prefix, startAfter string, recursive bool) <-chan ObjectInfo {
	objectCh := make(chan ObjectInfo, 1)

	if startAfter != "" && !strings.Contains(startAfter, prefix) {
		objectCh <- ObjectInfo{Err: errors.Errorf("wrong startAfter value %q for prefix %q", startAfter, prefix)}
		return objectCh
	}

	// remove leading slash from prefix
	prefix = strings.TrimPrefix(prefix, "/")

	fprefix := filepath.Join(s.dataDir, prefix)
	root := filepath.Dir(fprefix)
	if len(root) < len(s.dataDir) {
		root = s.dataDir
	}

	// remove leading slash
	startAfter = strings.TrimPrefix(startAfter, "/")

	go func(objectCh chan<- ObjectInfo) {
		defer func() {
			if util.ContextCanceled(ctx) {
				objectCh <- ObjectInfo{
					Err: ctx.Err(),
				}
			}
			close(objectCh)
		}()

		err := filepath.Walk(root, func(ep string, info os.FileInfo, err error) error {
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.WithStack(err)
			}
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			p := ep

			// get the path with / separator
			p = filepath.ToSlash(p)

			p, err = filepath.Rel(s.dataDir, p)
			if err != nil {
				return errors.WithStack(err)
			}
			if !recursive && len(p) > len(prefix) {
				rel := strings.TrimPrefix(p, prefix)
				skip := strings.Contains(rel, "/")

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

			if strings.HasPrefix(p, prefix) && p > startAfter {
				select {
				case objectCh <- ObjectInfo{Path: p, LastModified: info.ModTime(), Size: info.Size()}:
				case <-ctx.Done():
					return nil
				}
			}

			return nil
		})
		if err != nil {
			select {
			case objectCh <- ObjectInfo{Err: err}:
			case <-ctx.Done():
			}
			return
		}
	}(objectCh)

	return objectCh
}
