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

package unarchive

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

const (
	defaultDirPerm = 0755
)

func Unarchive(source io.Reader, destDir string, overwrite, removeDestDir bool) error {
	var err error
	destDir, err = filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("failed to calculate destination dir absolute path: %v", err)
	}
	// don't follow destdir if it's a symlink
	fi, err := os.Lstat(destDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to lstat destination dir: %v", err)
	}
	if fi != nil && !fi.IsDir() {
		return fmt.Errorf("destination path %q already exists and it's not a directory (mode: %q)", destDir, fi.Mode().String())
	}
	if fi != nil && fi.IsDir() && removeDestDir {
		if err := os.RemoveAll(destDir); err != nil {
			return fmt.Errorf("destination path %q already exists and it's not a directory (mode: %q)", destDir, fi.Mode().String())
		}
	}

	tr := tar.NewReader(source)

	for {
		err := untarNext(tr, destDir, overwrite)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading file in tar archive: %v", err)
		}
	}

	return nil
}

func untarNext(tr *tar.Reader, destDir string, overwrite bool) error {
	hdr, err := tr.Next()
	if err != nil {
		return err // don't wrap error; calling loop must break on io.EOF
	}
	destPath := filepath.Join(destDir, hdr.Name)
	log.Printf("file: %q", destPath)

	// do not overwrite existing files, if configured
	if !overwrite && fileExists(destPath) {
		return fmt.Errorf("file already exists: %s", destPath)
	}
	// if "to" is a file and now exits and it's not a file then remove it
	if err := os.RemoveAll(destPath); err != nil {
		return err
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		fi, err := os.Lstat(destPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if fi != nil && !fi.IsDir() {
			if err := os.RemoveAll(destPath); err != nil {
				return err
			}
		}
		return mkdir(destPath, hdr.FileInfo().Mode())
	case tar.TypeReg, tar.TypeRegA, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		fi, err := os.Lstat(destPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if fi != nil && !fi.Mode().IsRegular() {
			if err := os.RemoveAll(destPath); err != nil {
				return err
			}
		}
		return writeNewFile(destPath, tr, hdr.FileInfo().Mode())
	case tar.TypeSymlink:
		if fileExists(destPath) {
			if err := os.RemoveAll(destPath); err != nil {
				return err
			}
		}
		return writeNewSymbolicLink(destPath, hdr.Linkname)
	case tar.TypeLink:
		if fileExists(destPath) {
			if err := os.RemoveAll(destPath); err != nil {
				return err
			}
		}
		return writeNewHardLink(destPath, filepath.Join(destPath, hdr.Linkname))
	case tar.TypeXGlobalHeader:
		return nil // ignore the pax global header from git-generated tarballs
	default:
		return fmt.Errorf("%s: unknown type flag: %c", hdr.Name, hdr.Typeflag)
	}
}

func fileExists(name string) bool {
	_, err := os.Lstat(name)
	return !os.IsNotExist(err)
}

func mkdir(dirPath string, mode os.FileMode) error {
	err := os.MkdirAll(dirPath, mode)
	if err != nil {
		return fmt.Errorf("%s: making directory: %v", dirPath, err)
	}
	return nil
}

func writeNewFile(fpath string, in io.Reader, mode os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return fmt.Errorf("%s: making directory for file: %v", fpath, err)
	}

	out, err := os.Create(fpath)
	if err != nil {
		return fmt.Errorf("%s: creating new file: %v", fpath, err)
	}
	defer out.Close()

	err = out.Chmod(mode)
	if err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("%s: changing file mode: %v", fpath, err)
	}

	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("%s: writing file: %v", fpath, err)
	}
	return nil
}

func writeNewSymbolicLink(fpath string, target string) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return fmt.Errorf("%s: making directory for file: %v", fpath, err)
	}
	err = os.Symlink(target, fpath)
	if err != nil {
		return fmt.Errorf("%s: making symbolic link for: %v", fpath, err)
	}
	return nil
}

func writeNewHardLink(fpath string, target string) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return fmt.Errorf("%s: making directory for file: %v", fpath, err)
	}
	err = os.Link(target, fpath)
	if err != nil {
		return fmt.Errorf("%s: making hard link for: %v", fpath, err)
	}
	return nil
}
