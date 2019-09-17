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

package store

import (
	"fmt"
	"testing"
)

func TestOSTRunTaskIDFromArchivePath(t *testing.T) {
	tests := []struct {
		name        string
		archivePath string
		out         string
		err         error
	}{
		{
			name:        "test no runs 1",
			archivePath: "aaaa",
			err:         fmt.Errorf("wrong archive path %q", "aaaa"),
		},
		{
			name:        "test no runs 1",
			archivePath: "workspacearchives",
			err:         fmt.Errorf("wrong archive path %q", "workspacearchives"),
		},
		{
			name:        "test no runs 1",
			archivePath: "/workspacearchives/",
			err:         fmt.Errorf("wrong archive path %q", "/workspacearchives/"),
		},
		{
			name:        "test no runs 1",
			archivePath: "workspacearchives/2502c5c7-0fd9-432b-918e-3ccf31a664f8/data/3.tar",
			out:         "2502c5c7-0fd9-432b-918e-3ccf31a664f8",
		},
		{
			name:        "test no runs 1",
			archivePath: "workspacearchives/2502c5c7-0fd9-432b-918e-3ccf31a664f8/data/3.tar",
			out:         "2502c5c7-0fd9-432b-918e-3ccf31a664f8",
		},
		{
			name:        "test no runs 1",
			archivePath: "workspacearchives/2502c5c7-0fd9-432b-918e-3ccf31a664f8/data/3.tar",
			out:         "2502c5c7-0fd9-432b-918e-3ccf31a664f8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := OSTRunTaskIDFromPath(tt.archivePath)
			if err != nil {
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
				if id != tt.out {
					t.Fatalf("got id: %q, want id: %q", id, tt.out)
				}
			}
		})
	}
}
