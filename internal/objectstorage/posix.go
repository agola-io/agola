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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
)

const (
	dataDirName = "data"
	tmpDirName  = "tmp"
	splitLength = 8
)

func shouldEscape(c rune) bool {
	return c == '/' || c == '%'
}

// escape does percent encoding to '/' and adds a slash every 8 (of the original
// string) chars
func escape(s string) string {
	sepCount, hexCount := 0, 0
	nc := 0
	for _, c := range s {
		nc++
		if shouldEscape(c) {
			hexCount++
		}
		if nc%splitLength == 0 {
			sepCount++
		}
	}

	if sepCount == 0 && hexCount == 0 {
		return s
	}

	hasFileMarker := nc%splitLength == 0
	l := len(s) + sepCount + 2*hexCount
	// if the string length is a multiple of 8 then we have to add a file marker
	// ".f" to not ovverride a possible directory in our fs representation
	if hasFileMarker {
		l++
	}

	t := make([]byte, l)
	j := 0
	nc = 0
	for _, c := range s {
		nc++
		switch {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			s := string(c)
			for i := 0; i < len(s); i++ {
				t[j] = s[i]
				j++
			}
		}
		if nc%splitLength == 0 {
			t[j] = '/'
			j++
		}
	}

	// add file marker
	if hasFileMarker {
		t[j-1] = '.'
		t[j] = 'f'
	}

	return string(t)
}

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

type EscapeError string

func (e EscapeError) Error() string {
	return "invalid URL escape " + strconv.Quote(string(e))
}

func unescape(s string) (string, bool, error) {
	// number of percent encoded
	n := 0
	// number of slashes
	ns := 0
	// number of char in the unescaped string
	nc := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError {
			return "", false, errors.Errorf("bad UTF-8 string")
		}
		switch r {
		case '%':
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[:3]
				}
				return "", false, EscapeError(s)
			}
			i += 3
			nc++
		case '/':
			ns++
			if nc%splitLength != 0 {
				return "", false, EscapeError(s)
			}
			i++
		default:
			i += width
			nc++
		}
	}

	// check and remove trailing file marker
	hasFileMarker := false
	if nc > splitLength && nc%splitLength == 2 && s[len(s)-2:] == ".f" {
		hasFileMarker = true
		s = s[:len(s)-2]
		nc -= 2
	}

	if n == 0 && ns == 0 {
		return s, hasFileMarker, nil
	}

	// destination string is
	// the length of the escaped one (with the ending file marker already removed) - number of percent * 2 - number os slashes
	t := make([]byte, len(s)-n*2-ns)
	j := 0
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError {
			return "", false, errors.Errorf("bad UTF-8 string")
		}
		switch r {
		case '%':
			t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
			j++
			i += 3
		case '/':
			// skip "/"
			i++
		default:
			for k := 0; k < width; k++ {
				t[j] = s[i]
				j++
				i++
			}
		}
	}
	return string(t), hasFileMarker, nil
}

type PosixStorage struct {
	dataDir string
	tmpDir  string
}

func NewPosixStorage(baseDir string) (*PosixStorage, error) {
	if err := os.MkdirAll(baseDir, 0770); err != nil {
		return nil, err
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
	if p == "" {
		return "", errors.Errorf("empty key name")
	}
	return filepath.Join(s.dataDir, escape(p)), nil
}

func (s *PosixStorage) Stat(p string) (*ObjectInfo, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(fspath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotExist
		}
		return nil, err
	}

	return &ObjectInfo{Path: p, LastModified: fi.ModTime()}, nil
}

func (s *PosixStorage) ReadObject(p string) (ReadSeekCloser, error) {
	fspath, err := s.fsPath(p)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fspath)
	if err != nil && os.IsNotExist(err) {
		return nil, ErrNotExist
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
	return s.WriteFileAtomicFunc(fspath, 0660, persist, func(f io.Writer) error {
		_, err := io.Copy(f, data)
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
			return ErrNotExist
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

	fprefix := filepath.Join(s.dataDir, escape(prefix))
	root := filepath.Dir(fprefix)
	if len(root) < len(s.dataDir) {
		root = s.dataDir
	}

	// remove leading slash
	if strings.HasPrefix(startWith, "/") {
		startWith = strings.TrimPrefix(startWith, "/")
	}

	go func(objectCh chan<- ObjectInfo) {
		var prevp string
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
			p, _, err = unescape(p)
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

			// don't list dirs if there's not a file with the same name (with filemarker)
			// it's not an issue if the file in the meantime has been removed, it won't
			// just be listed
			hasFile := true
			_, err = os.Stat(ep + ".f")
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if os.IsNotExist(err) {
				hasFile = false
			}
			if info.IsDir() && !hasFile {
				return nil
			}

			if strings.HasPrefix(p, prefix) && p > startWith {
				// skip keys lesser than the previously returned one. This happens when we
				// receive a file with a file marker that we already returned previously
				// when we received a dir with the same name
				// it'not an issue if the dir has been removed since we already returned the file
				if p > prevp {
					select {
					// Send object content.
					case objectCh <- ObjectInfo{Path: p, LastModified: info.ModTime()}:
					// If receives done from the caller, return here.
					case <-doneCh:
						return io.EOF
					}
				}
				prevp = p
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

// WriteFileAtomicFunc atomically writes a file, it achieves this by creating a
// temporary file and then moving it. writeFunc is the func that will write
// data to the file.
// TODO(sgotti) remove left over tmp files if process crashes before calling
// os.Remove
func (s *PosixStorage) WriteFileAtomicFunc(p string, perm os.FileMode, persist bool, writeFunc func(f io.Writer) error) error {
	f, err := ioutil.TempFile(s.tmpDir, "tmpfile")
	if err != nil {
		return err
	}
	err = writeFunc(f)
	if persist && err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if permErr := os.Chmod(f.Name(), perm); err == nil {
		err = permErr
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}

	if !persist {
		return nil
	}
	// sync parent dirs
	pdir := filepath.Dir(p)
	for {
		if !strings.HasPrefix(pdir, s.dataDir) {
			break
		}
		f, err := os.Open(pdir)
		if err != nil {
			f.Close()
			return nil
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil
		}
		f.Close()

		pdir = filepath.Dir(pdir)
	}
	return nil
}

func (s *PosixStorage) WriteFileAtomic(filename string, perm os.FileMode, persist bool, data []byte) error {
	return s.WriteFileAtomicFunc(filename, perm, persist,
		func(f io.Writer) error {
			_, err := f.Write(data)
			return err
		})
}
