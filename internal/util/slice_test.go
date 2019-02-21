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

func TestCompareStringSlice(t *testing.T) {
	tests := []struct {
		a  []string
		b  []string
		ok bool
	}{
		{[]string{}, []string{}, true},
		{[]string{"", ""}, []string{""}, false},
		{[]string{"", ""}, []string{"", ""}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{"a", "b", "c"}, []string{"a", "b"}, false},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"a", "b", "c"}, []string{"b", "c", "a"}, false},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, false},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, false},
	}

	for i, tt := range tests {
		ok := CompareStringSlice(tt.a, tt.b)
		if ok != tt.ok {
			t.Errorf("%d: got %t but wanted: %t a: %v, b: %v", i, ok, tt.ok, tt.a, tt.b)
		}
	}
}

func TestCompareStringSliceNoOrder(t *testing.T) {
	tests := []struct {
		a  []string
		b  []string
		ok bool
	}{
		{[]string{}, []string{}, true},
		{[]string{"", ""}, []string{""}, false},
		{[]string{"", ""}, []string{"", ""}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},
		{[]string{"a", "b", "c"}, []string{"a", "b"}, false},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"a", "b", "c"}, []string{"b", "c", "a"}, true},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, false},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, false},
	}

	for i, tt := range tests {
		ok := CompareStringSliceNoOrder(tt.a, tt.b)
		if ok != tt.ok {
			t.Errorf("%d: got %t but wanted: %t a: %v, b: %v", i, ok, tt.ok, tt.a, tt.b)
		}
	}
}

func TestDifference(t *testing.T) {
	tests := []struct {
		a []string
		b []string
		r []string
	}{
		{[]string{}, []string{}, []string{}},
		{[]string{"", ""}, []string{""}, []string{}},
		{[]string{"", ""}, []string{"", ""}, []string{}},
		{[]string{"", ""}, []string{"a", "", "b"}, []string{}},
		{[]string{"a", "b"}, []string{"a", "b"}, []string{}},
		{[]string{"a", "b"}, []string{"b", "a"}, []string{}},
		{[]string{"a", "b", "c"}, []string{}, []string{"a", "b", "c"}},
		{[]string{"a", "b", "c"}, []string{"a", "b"}, []string{"c"}},
		{[]string{"a", "b"}, []string{"a", "b", "c"}, []string{}},
		{[]string{"a", "b"}, []string{"c", "a", "b"}, []string{}},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, []string{}},
		{[]string{"a", "b", "c"}, []string{"b", "c", "a"}, []string{}},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, []string{}},
		{[]string{"a", "b", "c", "a"}, []string{"a", "c", "b", "b"}, []string{}},
	}

	for i, tt := range tests {
		r := Difference(tt.a, tt.b)
		if !CompareStringSliceNoOrder(r, tt.r) {
			t.Errorf("%d: got %v but wanted: %v a: %v, b: %v", i, r, tt.r, tt.a, tt.b)
		}
	}
}
