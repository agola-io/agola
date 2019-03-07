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

package config

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/util"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name string
		in   string
		err  error
	}{
		{
			name: "test no pipelines 1",
			in:   ``,
			err:  fmt.Errorf(`no pipelines defined`),
		},
		{
			name: "test no pipelines 2",
			in: `
                pipelines:
                `,
			err: fmt.Errorf(`no pipelines defined`),
		},
		{
			name: "test empty pipeline",
			in: `
                pipelines:
                  pipeline01:
                `,
			err: fmt.Errorf(`pipeline "pipeline01" is empty`),
		},
		{
			name: "test missing element dependency",
			in: `
                tasks:
                  task0k1:
                    environment:
                      ENV01: ENV01

                pipelines:
                  pipeline01:
                    elements:
                      element01:
                        task: task01
                        depends:
                          - element02
                `,
			err: fmt.Errorf(`pipeline element "element02" needed by element "element01" doesn't exist`),
		},
		{
			name: "test circular dependency between 2 elements a -> b -> a",
			in: `
                tasks:
                  task01:
                    environment:
                      ENV01: ENV01

                pipelines:
                  pipeline01:
                    elements:
                      element01:
                        task: task01
                        depends:
                          - element02
                      element02:
                        task: task01
                        depends:
                          - element01
                `,
			err: &util.Errors{
				Errs: []error{
					errors.Errorf("circular dependency between element %q and elements %q", "element01", "element02"),
					errors.Errorf("circular dependency between element %q and elements %q", "element02", "element01"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.in)); err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, expected no error", err)
				}
				if errs, ok := err.(*util.Errors); ok {
					if !errs.Equal(tt.err) {
						t.Fatalf("got error: %v, want error: %v", err, tt.err)
					}
				} else {
					if err.Error() != tt.err.Error() {
						t.Fatalf("got error: %v, want error: %v", err, tt.err)
					}
				}
				return
			}
			if tt.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.err)
			}
		})
	}
}
