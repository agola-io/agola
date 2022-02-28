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
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"agola.io/agola/internal/errors"
)

const (
	defaultDirPerm = 0755
)

func Unarchive(source io.Reader, destDir string, overwrite, removeDestDir bool) error {
	var err error
	destDir, err = filepath.Abs(destDir)
	if err != nil {
		return errors.Wrapf(err, "failed to calculate destination dir absolute path")
	}
	// don't follow destdir if it's a symlink
	fi, err := os.Lstat(destDir)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to lstat destination dir")
	}
	if fi != nil && !fi.IsDir() {
		return errors.Errorf(
			"destination path %q already exists and it's not a directory (mode: %q)",
			destDir,
			fi.Mode().String(),
		)
	}
	if fi != nil && fi.IsDir() && removeDestDir {
		if err := os.RemoveAll(destDir); err != nil {
			return errors.Errorf(
				"destination path %q already exists and it's not a directory (mode: %q)",
				destDir,
				fi.Mode().String(),
			)
		}
	}

	tr := tar.NewReader(source)

	for {
		err := untarNext(tr, destDir, overwrite)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Wrapf(err, "error reading file in tar archive")
		}
	}

	return nil
}

func untarNext(tr *tar.Reader, destDir string, overwrite bool) error {
	hdr, err := tr.Next()
	if err != nil {
		return errors.WithStack(err)
	}
	destPath := filepath.Join(destDir, hdr.Name)
	log.Printf("file: %q", destPath)

	// do not overwrite existing files, if configured
	if !overwrite && fileExists(destPath) {
		return errors.Errorf("file already exists: %s", destPath)
	}
	// if "to" is a file and now exits and it's not a file then remove it
	if err := os.RemoveAll(destPath); err != nil {
		return errors.WithStack(err)
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		fi, err := os.Lstat(destPath)
		if err != nil && !os.IsNotExist(err) {
			return errors.WithStack(err)
		}
		if fi != nil && !fi.IsDir() {
			if err := os.RemoveAll(destPath); err != nil {
				return errors.WithStack(err)
			}
		}
		return mkdir(destPath, hdr.FileInfo().Mode())
	case tar.TypeReg, tar.TypeRegA, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		fi, err := os.Lstat(destPath)
		if err != nil && !os.IsNotExist(err) {
			return errors.WithStack(err)
		}
		if fi != nil && !fi.Mode().IsRegular() {
			if err := os.RemoveAll(destPath); err != nil {
				return errors.WithStack(err)
			}
		}
		return writeNewFile(destPath, tr, hdr.FileInfo().Mode())
	case tar.TypeSymlink:
		if fileExists(destPath) {
			if err := os.RemoveAll(destPath); err != nil {
				return errors.WithStack(err)
			}
		}
		return writeNewSymbolicLink(destPath, hdr.Linkname)
	case tar.TypeLink:
		if fileExists(destPath) {
			if err := os.RemoveAll(destPath); err != nil {
				return errors.WithStack(err)
			}
		}
		return writeNewHardLink(destPath, filepath.Join(destPath, hdr.Linkname))
	case tar.TypeXGlobalHeader:
		return nil // ignore the pax global header from git-generated tarballs
	default:
		return errors.Errorf("%s: unknown type flag: %c", hdr.Name, hdr.Typeflag)
	}
}

func fileExists(name string) bool {
	_, err := os.Lstat(name)
	return !os.IsNotExist(err)
}

func mkdir(dirPath string, mode os.FileMode) error {
	err := os.MkdirAll(dirPath, mode)
	if err != nil {
		return errors.Wrapf(err, "%s: making directory", dirPath)
	}
	return nil
}

func writeNewFile(fpath string, in io.Reader, mode os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return errors.Wrapf(err, "%s: making directory for file", fpath)
	}

	out, err := os.Create(fpath)
	if err != nil {
		return errors.Wrapf(err, "%s: creating new file", fpath)
	}
	defer out.Close()

	err = out.Chmod(mode)
	if err != nil && runtime.GOOS != "windows" {
		return errors.Wrapf(err, "%s: changing file mode", fpath)
	}

	_, err = io.Copy(out, in)
	if err != nil {
		return errors.Wrapf(err, "%s: writing file", fpath)
	}
	return nil
}

func writeNewSymbolicLink(fpath string, target string) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return errors.Wrapf(err, "%s: making directory for file", fpath)
	}
	err = os.Symlink(target, fpath)
	if err != nil {
		return errors.Wrapf(err, "%s: making symbolic link for", fpath)
	}
	return nil
}

func writeNewHardLink(fpath string, target string) error {
	err := os.MkdirAll(filepath.Dir(fpath), defaultDirPerm)
	if err != nil {
		return errors.Wrapf(err, "%s: making directory for file", fpath)
	}
	err = os.Link(target, fpath)
	if err != nil {
		return errors.Wrapf(err, "%s: making hard link for", fpath)
	}
	return nil
}
