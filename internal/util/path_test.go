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
	"reflect"
	"testing"
)

func TestPathList(t *testing.T) {
	tests := []struct {
		in  string
		out []string
	}{
		{"/path", []string{"path"}},
		{"path", []string{"path"}},
		{"/path/", []string{"path"}},
		{"path/", []string{"path"}},
		{"//path/", []string{"path"}},
		{"///path///", []string{"path"}},
		{"/path/to/file", []string{"path", "to", "file"}},
		{"path/to/file", []string{"path", "to", "file"}},
		{"/path/to/file/", []string{"path", "to", "file"}},
		{"path/to/file/", []string{"path", "to", "file"}},
		{"path/to/file///", []string{"path", "to", "file"}},
		{"///path///to///file///", []string{"path", "to", "file"}},
	}

	for _, tt := range tests {
		t.Run("test is parent path", func(t *testing.T) {
			out := PathList(tt.in)
			if !reflect.DeepEqual(out, tt.out) {
				t.Errorf("got %q but wanted: %q", out, tt.out)
			}
		})
	}
}

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
