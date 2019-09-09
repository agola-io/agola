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

package util

import (
	"path"
	"strings"
)

// PathHierarchy return a slice of paths from the base path (root included as . or / ).
// I.E. for a path like "path/to/file" it'll return a slice of these elements:
// ".", "path", "path/to", "path/to/file"
// for a path like "/path/to/file" it'll return a slice of these elements:
// "/", "/path", "/path/to", "/path/to/file"

func PathHierarchy(p string) []string {
	paths := []string{}
	for {
		paths = append([]string{p}, paths...)
		prevp := p
		p = path.Dir(p)
		if p == prevp {
			break
		}
	}
	return paths
}

// PathList return a slice of paths from the base path (root exluded as . or / ).
// I.E. for a path like "path/to/file" or "/path/to/file" it'll return a slice of these elements:
// "path", "to", "file"
func PathList(p string) []string {
	p = path.Clean(p)
	paths := []string{}
	for {
		paths = append([]string{path.Base(p)}, paths...)
		p = path.Dir(p)
		if p == "." || p == "/" {
			break
		}
	}
	return paths
}

// IsParentPath returns if the provided parent is parent of p
// parent and p paths must use slash "/" separators and must be absolute paths
func IsParentPath(parent, p string) bool {
	// add ending / to avoid names with common prefix, like:
	// /path/to
	// /path/t
	if !strings.HasSuffix(parent, "/") {
		parent = parent + "/"
	}
	return strings.Contains(p, parent)
}

// IsParentPath returns if the provided parent the same path as p or a parent of p
// parent and p paths must use slash "/" separators
func IsSameOrParentPath(parent, p string) bool {
	if parent == p {
		return true
	}
	return IsParentPath(parent, p)
}
