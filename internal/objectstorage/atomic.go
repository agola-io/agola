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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// writeFileAtomicFunc atomically writes a file, it achieves this by creating a
// temporary file and then moving it. writeFunc is the func that will write
// data to the file.
// TODO(sgotti) remove left over tmp files if process crashes before calling
// os.Remove
func writeFileAtomicFunc(p, baseDir, tmpDir string, perm os.FileMode, persist bool, writeFunc func(f io.Writer) error) error {
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

/*
func writeFileAtomic(filename, baseDir, tmpDir string, perm os.FileMode, persist bool, data []byte) error {
	return writeFileAtomicFunc(filename, baseDir, tmpDir, perm, persist,
		func(f io.Writer) error {
			_, err := f.Write(data)
			return err
		})
}
*/
