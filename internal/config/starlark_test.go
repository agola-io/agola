// Copyright 2020 Sorint.lab
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

package config

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.starlark.net/starlark"
)

func TestStarlarkJSON(t *testing.T) {

	tests := []struct {
		name string
		in   starlark.Value
		out  string
		err  error
	}{
		{
			name: "test key as a string",
			in: func() starlark.Value {
				s := &starlark.Dict{}
				_ = s.SetKey(starlark.String("key"), starlark.String("string01"))
				return starlark.Value(s)
			}(),
			out: `{"key": "string01"}`,
		},
		{
			name: "test key not a string",
			in: func() starlark.Value {
				s := &starlark.Dict{}
				_ = s.SetKey(starlark.MakeInt(10), starlark.String("string01"))
				return starlark.Value(s)
			}(),
			err: fmt.Errorf("cannot convert non-string dict key to JSON"),
		},
		{
			name: "test list",
			in: func() starlark.Value {
				l := []starlark.Value{
					starlark.String("\ns\ttring01"),
					starlark.MakeInt(10),
					starlark.Bool(true),
					starlark.Float(math.MaxFloat64),
					func() starlark.Value {
						s := &starlark.Dict{}
						_ = s.SetKey(starlark.String("key"), starlark.String("string01"))
						return starlark.Value(s)
					}(),
				}
				return starlark.NewList(l)
			}(),
			out: `["\ns\ttring01", 10, true, 1.7976931348623157e+308, {"key": "string01"}]`,
		},
		{
			name: "test string special chars",
			in:   starlark.String("\ns\ttring01"),
			out:  `"\ns\ttring01"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := new(bytes.Buffer)
			if err := starlarkJSON(out, tt.in); err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, expected no error", err)
				}
				if err.Error() != tt.err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
			} else {
				if tt.err != nil {
					t.Fatalf("got nil error, want error: %v", tt.err)
				}
			}

			if tt.err == nil {
				if diff := cmp.Diff(tt.out, out.String()); diff != "" {
					t.Fatalf(diff)
				}
			}
		})
	}
}
