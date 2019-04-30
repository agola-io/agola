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
