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

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
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
			} else {
				if tt.err != nil {
					t.Fatalf("got nil error, want error: %v", tt.err)
				}
			}
		})
	}
}

func TestParseOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  *Config
	}{
		{
			name: "test element when conditions",
			in: `
                runtimes:
                  runtime01:
                    type: pod
                    containers:
                      - image: image01
                        environment:
                          ENV01: ENV01
                          ENVFROMVARIABLE01:
                            from_variable: variable01

                tasks:
                  task01:
                    runtime: runtime01
                    environment:
                      ENV01: ENV01
                      ENVFROMVARIABLE01:
                        from_variable: variable01
                    steps:
                      - run: command01
                      - run:
                          name: name different than command
                          command: command02
                      - run:
                          command: command03
                          environment:
                            ENV01: ENV01
                            ENVFROMVARIABLE01:
                              from_variable: variable01

                pipelines:
                  pipeline01:
                    elements:
                      element01:
                        task: task01
                        when:
                          branch: master
                          tag:
                            - v1.x
                            - v2.x
                          ref:
                            include: master
                            exclude: [ /branch01/ , branch02 ]
          `,
			out: &Config{
				Runtimes: map[string]*Runtime{
					"runtime01": &Runtime{
						Name: "runtime01",
						Type: "pod",
						Arch: "",
						Containers: []*Container{
							&Container{
								Image: "image01",
								Environment: map[string]Value{
									"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
									"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
								},
								User: "",
							},
						},
					},
				},
				Tasks: map[string]*Task{
					"task01": &Task{
						Name:    "task01",
						Runtime: "runtime01",
						Environment: map[string]Value{
							"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
							"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
						},
						WorkingDir: "",
						Shell:      "",
						User:       "",
						Steps: []interface{}{
							&RunStep{
								Step: Step{
									Type: "run",
									Name: "command01",
								},
								Command: "command01",
							},
							&RunStep{
								Step: Step{
									Type: "run",
									Name: "name different than command",
								},
								Command: "command02",
							},
							&RunStep{
								Step: Step{
									Type: "run",
									Name: "command03",
								},
								Command: "command03",
								Environment: map[string]Value{
									"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
									"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
								},
							},
						},
					},
				},
				Pipelines: map[string]*Pipeline{
					"pipeline01": &Pipeline{
						Name: "pipeline01",
						Elements: map[string]*Element{
							"element01": &Element{
								Name:          "element01",
								Task:          "task01",
								Depends:       []*Depend{},
								IgnoreFailure: false,
								Approval:      false,
								When: &types.When{
									Branch: &types.WhenConditions{
										Include: []types.WhenCondition{
											{Type: types.WhenConditionTypeSimple, Match: "master"},
										},
									},
									Tag: &types.WhenConditions{
										Include: []types.WhenCondition{
											{Type: types.WhenConditionTypeSimple, Match: "v1.x"},
											{Type: types.WhenConditionTypeSimple, Match: "v2.x"},
										},
									},
									Ref: &types.WhenConditions{
										Include: []types.WhenCondition{
											{Type: types.WhenConditionTypeSimple, Match: "master"},
										},
										Exclude: []types.WhenCondition{
											{Type: types.WhenConditionTypeRegExp, Match: "branch01"},
											{Type: types.WhenConditionTypeSimple, Match: "branch02"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ParseConfig([]byte(tt.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}
