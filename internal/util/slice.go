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

import "sort"

func StringInSlice(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

// CompareStringSlice compares two slices of strings, a nil slice is considered an empty one
func CompareStringSlice(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// CompareStringSliceNoOrder compares two slices of strings regardless of their order, a nil slice is considered an empty one
func CompareStringSliceNoOrder(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// This isn't the faster way but it's cleaner and enough for us

	// Take a copy of the original slice
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)

	sort.Sort(sort.StringSlice(a))
	sort.Sort(sort.StringSlice(b))

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// CommonElements return the common elements in two slices of strings
func CommonElements(a []string, b []string) []string {
	common := []string{}
	for _, v := range a {
		if StringInSlice(b, v) {
			common = append(common, v)
		}
	}
	return common
}

// Difference returns elements in a - b
func Difference(a []string, b []string) []string {
	diff := []string{}
	for _, v := range a {
		if !StringInSlice(b, v) {
			diff = append(diff, v)
		}
	}
	return diff
}
