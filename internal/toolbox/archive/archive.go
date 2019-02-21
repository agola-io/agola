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

package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/bmatcuk/doublestar"
)

type Archive struct {
	ArchiveInfos []*ArchiveInfo
	OutFile      string
}

type ArchiveInfo struct {
	SourceDir string
	DestDir   string
	Paths     []string
}

func CreateTar(archiveInfos []*ArchiveInfo, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	// check duplicate files
	seenDestPaths := map[string]struct{}{}

	for _, ai := range archiveInfos {
		sourceDir := ai.SourceDir
		destDir := ai.DestDir

		sourceDirInfo, err := os.Stat(sourceDir)
		if err != nil {
			return fmt.Errorf("%s: stat: %v", sourceDir, err)
		}
		if !sourceDirInfo.IsDir() {
			return fmt.Errorf("sourceDir %q is not a directory", sourceDir)
		}
		err = filepath.Walk(sourceDir, func(path string, fi os.FileInfo, err error) error {
			// skip sourceDir
			if path == sourceDir {
				return nil
			}

			if err != nil {
				return fmt.Errorf("error accessing path %q: %v. Skipping.", path, err)
			}
			match := false
			for _, pattern := range ai.Paths {
				rel, err := filepath.Rel(sourceDir, path)
				if err != nil {
					return err
				}
				ok, err := doublestar.Match(pattern, rel)
				if err != nil {
					return err
				}
				if ok {
					match = true
					break
				}
			}
			if !match {
				return nil
			}
			log.Printf("matched file: %q\n", path)

			// generate the path to save in the header
			destPath, err := archivePath(sourceDirInfo, sourceDir, destDir, path)
			if err != nil {
				return err
			}
			if _, ok := seenDestPaths[destPath]; ok {
				return fmt.Errorf("archive destination path %q already exists. Source path: %q", destPath, path)
			}
			seenDestPaths[destPath] = struct{}{}

			// skip sockets (not supported by tar)
			if fi.Mode()&os.ModeSocket != 0 {
				return nil
			}

			var linkTarget string
			if fi.Mode()&os.ModeSymlink != 0 {
				var err error
				linkTarget, err = os.Readlink(path)
				if err != nil {
					return fmt.Errorf("%s: readlink: %v", path, err)
				}
			}

			hdr, err := tar.FileInfoHeader(fi, filepath.ToSlash(linkTarget))
			if err != nil {
				return fmt.Errorf("%s: making header: %v", path, err)
			}
			hdr.Name = destPath

			err = tw.WriteHeader(hdr)
			if err != nil {
				return fmt.Errorf("%s: writing header: %v", hdr.Name, err)
			}

			if fi.IsDir() {
				return nil
			}

			if fi.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return fmt.Errorf("%s: copying contents: %v", f.Name(), err)
				}
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking the path %q: %v\n", sourceDir, err)
		}
	}

	return nil
}

func archivePath(sourceDirInfo os.FileInfo, sourceDir, baseDir, fpath string) (string, error) {
	// Remove root slash
	rooted := filepath.IsAbs(baseDir)
	if rooted {
		var err error
		baseDir, err = filepath.Rel("/", baseDir)
		if err != nil {
			return "", err
		}
	}
	if !sourceDirInfo.IsDir() {
		return "", fmt.Errorf("sourceDir %q is not a directory", sourceDir)
	}

	rel, err := filepath.Rel(sourceDir, fpath)
	if err != nil {
		return "", err
	}
	return path.Join(baseDir, rel), nil
}
