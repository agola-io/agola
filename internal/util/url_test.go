// Copyright 2025 Sorint.lab
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

package util_test

import (
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
)

func TestExpandURLDefaultPorts(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in   string
		want []string
	}{
		{
			name: "http without port",
			in:   "http://localhost",
			want: []string{"http://localhost", "http://localhost:80"},
		},
		{
			name: "https without port",
			in:   "https://localhost",
			want: []string{"https://localhost", "https://localhost:443"},
		},
		{
			name: "http with default port",
			in:   "http://localhost:80",
			want: []string{"http://localhost", "http://localhost:80"},
		},
		{
			name: "https with default port",
			in:   "https://localhost:443",
			want: []string{"https://localhost", "https://localhost:443"},
		},
		{
			name: "http with custom port",
			in:   "http://localhost:8080",
			want: []string{"http://localhost:8080"},
		},
		{
			name: "https with custom port",
			in:   "https://localhost:8443",
			want: []string{"https://localhost:8443"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.in)
			testutil.NilError(t, err)

			outURLs := util.ExpandURLDefaultPorts(u)
			// TODO: update the condition below to compare got with tt.want.

			out := []string{}
			for _, outURL := range outURLs {
				out = append(out, outURL.String())
			}

			assert.Assert(t, cmp.DeepEqual(tt.want, out), "expected urls")
		})
	}
}
