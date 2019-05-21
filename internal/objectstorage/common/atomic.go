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

package common

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomicFunc atomically writes a file, it achieves this by creating a
// temporary file and then moving it. writeFunc is the func that will write
// data to the file.
// TODO(sgotti) remove left over tmp files if process crashes before calling
// os.Remove
func WriteFileAtomicFunc(p, baseDir, tmpDir string, perm os.FileMode, persist bool, writeFunc func(f io.Writer) error) error {
	f, err := ioutil.TempFile(tmpDir, "tmpfile")
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
		if !strings.HasPrefix(pdir, baseDir) {
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

func WriteFileAtomic(filename, baseDir, tmpDir string, perm os.FileMode, persist bool, data []byte) error {
	return WriteFileAtomicFunc(filename, baseDir, tmpDir, perm, persist,
		func(f io.Writer) error {
			_, err := f.Write(data)
			return err
		})
}
