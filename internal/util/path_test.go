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

import "testing"

func TestIsParentPath(t *testing.T) {
	tests := []struct {
		parent string
		p      string
		ok     bool
	}{
		{"/", "/a", true},
		{"/a", "/a", false},
		{"/path/to", "/path/to/file", true},
		{"/path/to/", "/path/to/file", true},
		{"/path/to/f", "/path/to/file", false},
		{"/path/t", "/path/to/file", false},
	}

	for _, tt := range tests {
		t.Run("test is parent path", func(t *testing.T) {
			ok := IsParentPath(tt.parent, tt.p)
			if ok != tt.ok {
				t.Errorf("got %t but wanted: %t a: %v, b: %v", ok, tt.ok, tt.parent, tt.p)
			}
		})
	}
}

func TestIsSameOrParentPath(t *testing.T) {
	tests := []struct {
		parent string
		p      string
		ok     bool
	}{
		{"/", "/a", true},
		{"/a", "/a", true},
		{"/path/to", "/path/to/file", true},
		{"/path/to/", "/path/to/file", true},
		{"/path/to/f", "/path/to/file", false},
		{"/path/t", "/path/to/file", false},
		{"/path/to/file", "/path/to/file", true},
		{"/path/to/file", "/path/to/file2", false},
		{"/path/to/file", "/path/to/fil", false},
	}

	for _, tt := range tests {
		t.Run("test is parent path", func(t *testing.T) {
			ok := IsSameOrParentPath(tt.parent, tt.p)
			if ok != tt.ok {
				t.Errorf("got %t but wanted: %t a: %v, b: %v", ok, tt.ok, tt.parent, tt.p)
			}
		})
	}
}
