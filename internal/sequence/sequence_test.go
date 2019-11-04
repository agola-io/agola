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

package sequence

import (
	"errors"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestString(t *testing.T) {
	tests := []struct {
		name string
		in   *Sequence
		out  string
	}{
		{
			name: "test zero value",
			in: &Sequence{
				Epoch: 0,
				C:     0,
			},
			out: "0000000000000-0000000000000",
		},
		{
			name: "test one value",
			in: &Sequence{
				Epoch: 1,
				C:     1,
			},
			out: "0000000000001-0000000000001",
		},
		{
			name: "test 32 value",
			in: &Sequence{
				Epoch: 32,
				C:     32,
			},
			out: "0000000000010-0000000000010",
		},
		{
			name: "test max uint 32 value",
			in: &Sequence{
				Epoch: math.MaxUint32,
				C:     math.MaxUint32,
			},
			out: "0000003vvvvvv-0000003vvvvvv",
		},
		{
			name: "test max value",
			in: &Sequence{
				Epoch: math.MaxUint64,
				C:     math.MaxUint64,
			},
			out: "fvvvvvvvvvvvv-fvvvvvvvvvvvv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := tt.in.String()
			if out != tt.out {
				t.Fatalf("expected %q, got %q", tt.out, out)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  *Sequence
		err  error
	}{
		{
			name: "test zero value",
			in:   "0000000000000-0000000000000",
			out: &Sequence{
				Epoch: 0,
				C:     0,
			},
		},
		{
			name: "test one value",
			in:   "0000000000001-0000000000001",
			out: &Sequence{
				Epoch: 1,
				C:     1,
			},
		},
		{
			name: "test 32 value",
			in:   "0000000000010-0000000000010",
			out: &Sequence{
				Epoch: 32,
				C:     32,
			},
		},
		{
			name: "test max uint 32 value",
			in:   "0000003vvvvvv-0000003vvvvvv",
			out: &Sequence{
				Epoch: math.MaxUint32,
				C:     math.MaxUint32,
			},
		},
		{
			name: "test max value",
			in:   "fvvvvvvvvvvvv-fvvvvvvvvvvvv",
			out: &Sequence{
				Epoch: math.MaxUint64,
				C:     math.MaxUint64,
			},
		},
		{
			name: "test wrong string length",
			in:   "fvvvvvvvvvvvv-fvvvvvvvvvvv",
			out: &Sequence{
				Epoch: math.MaxUint64,
				C:     math.MaxUint64,
			},
			err: errors.New(`bad sequence "fvvvvvvvvvvvv-fvvvvvvvvvvv" string length`),
		},
		{
			name: "test wrong string format",
			in:   "fvvvvvvvvvvvv-fvvv-vvvvvvvv",
			out: &Sequence{
				Epoch: math.MaxUint64,
				C:     math.MaxUint64,
			},
			err: errors.New(`bad sequence "fvvvvvvvvvvvv-fvvv-vvvvvvvv"`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Parse(tt.in)
			if err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, want nil error", err)
				}
				if tt.err.Error() != err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
				return
			} else if tt.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.err)
			}
			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
