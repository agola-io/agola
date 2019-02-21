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

func isSymlink(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSymlink != 0
}
