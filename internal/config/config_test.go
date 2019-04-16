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
			name: "test no runs 1",
			in:   ``,
			err:  fmt.Errorf(`no runs defined`),
		},
		{
			name: "test no runs 2",
			in: `
                runs:
                `,
			err: fmt.Errorf(`no runs defined`),
		},
		{
			name: "test empty run",
			in: `
                runs:
                  -
                `,
			err: fmt.Errorf(`run at index 0 is empty`),
		},
		{
			name: "test empty task",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - 
                `,
			err: fmt.Errorf(`run "run01": task at index 0 is empty`),
		},
		{
			name: "test missing task dependency",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task02
                `,
			err: fmt.Errorf(`run task "task02" needed by task "task01" doesn't exist`),
		},
		{
			name: "test circular dependency between 2 tasks a -> b -> a",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task02
                      - name: task02
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task01
                `,
			err: &util.Errors{
				Errs: []error{
					errors.Errorf("circular dependency between task %q and tasks %q", "task01", "task02"),
					errors.Errorf("circular dependency between task %q and tasks %q", "task02", "task01"),
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
			name: "test task all options",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          auth:
                            username: username
                            password:
                              from_variable: password
                          containers:
                            - image: image01
                              auth:
                                username:
                                  from_variable: username2
                                password: password2
                              environment:
                                ENV01: ENV01
                                ENVFROMVARIABLE01:
                                  from_variable: variable01
                        environment:
                          ENV01: ENV01
                          ENVFROMVARIABLE01:
                            from_variable: variable01
                        steps:
                          # normal step definition
                          - type: clone
                          - type: run
                            command: command01
                          - type: run
                            name: name different than command
                            command: command02
                          - type: run
                            command: command03
                            environment:
                              ENV01: ENV01
                              ENVFROMVARIABLE01:
                                from_variable: variable01
                          - type: save_cache
                            key: cache-{{ arch }}
                            contents:
                              - source_dir: /go/pkg/mod/cache

                          # simpler (for yaml not for json) steps definition
                          - clone:
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
                          - save_cache:
                              key: cache-{{ arch }}
                              contents:
                                - source_dir: /go/pkg/mod/cache
                        when:
                          branch: master
                          tag:
                            - v1.x
                            - v2.x
                          ref:
                            include: master
                            exclude: [ /branch01/ , branch02 ]
                        depends:
                          - task: task02
                            conditions:
                              - on_success
                              - on_failure
                          - task03
                          - task04:
                            - on_success
                      - name: task02
                        runtime:
                          type: pod
                          containers:
                            - image: image01
                      - name: task03
                        runtime:
                          type: pod
                          containers:
                            - image: image01
                      - name: task04
                        runtime:
                          type: pod
                          containers:
                            - image: image01
          `,
			out: &Config{
				Runs: []*Run{
					&Run{
						Name: "run01",
						Tasks: []*Task{
							&Task{
								Name: "task01",
								Runtime: &Runtime{
									Type: "pod",
									Auth: &RegistryAuth{
										Type:     RegistryAuthTypeDefault,
										Username: Value{Type: ValueTypeString, Value: "username"},
										Password: Value{Type: ValueTypeFromVariable, Value: "password"},
									},
									Arch: "",
									Containers: []*Container{
										&Container{
											Image: "image01",
											Auth: &RegistryAuth{
												Type:     RegistryAuthTypeDefault,
												Username: Value{Type: ValueTypeFromVariable, Value: "username2"},
												Password: Value{Type: ValueTypeString, Value: "password2"},
											},
											Environment: map[string]Value{
												"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
												"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
											},
											User: "",
										},
									},
								},
								Environment: map[string]Value{
									"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
									"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
								},
								WorkingDir: "",
								Shell:      "",
								User:       "",
								Steps: []interface{}{
									&CloneStep{Step: Step{Type: "clone"}},
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
									&SaveCacheStep{
										Step:     Step{Type: "save_cache"},
										Key:      "cache-{{ arch }}",
										Contents: []*SaveContent{&SaveContent{SourceDir: "/go/pkg/mod/cache", Paths: []string{"**"}}},
									},
									&CloneStep{Step: Step{Type: "clone"}},
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
									&SaveCacheStep{
										Step:     Step{Type: "save_cache"},
										Key:      "cache-{{ arch }}",
										Contents: []*SaveContent{&SaveContent{SourceDir: "/go/pkg/mod/cache", Paths: []string{"**"}}},
									},
								},
								IgnoreFailure: false,
								Approval:      false,
								When: &types.When{
									Branch: &types.WhenConditions{Include: []types.WhenCondition{{Match: "master"}}},
									Tag:    &types.WhenConditions{Include: []types.WhenCondition{{Match: "v1.x"}, {Match: "v2.x"}}},
									Ref: &types.WhenConditions{
										Include: []types.WhenCondition{{Match: "master"}},
										Exclude: []types.WhenCondition{{Match: "/branch01/", Type: types.WhenConditionTypeRegExp}, {Match: "branch02"}},
									}},
								Depends: []*Depend{
									&Depend{TaskName: "task02", Conditions: []DependCondition{DependConditionOnSuccess, DependConditionOnFailure}},
									&Depend{TaskName: "task03", Conditions: nil},
									&Depend{TaskName: "task04", Conditions: []DependCondition{DependConditionOnSuccess}},
								},
							},
							&Task{
								Name: "task02",
								Runtime: &Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*Container{
										&Container{
											Image: "image01",
										},
									},
								},
								WorkingDir: defaultWorkingDir,
								Steps:      []interface{}{},
								Depends:    []*Depend{},
							},
							&Task{
								Name: "task03",
								Runtime: &Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*Container{
										&Container{
											Image: "image01",
										},
									},
								},
								WorkingDir: defaultWorkingDir,
								Steps:      []interface{}{},
								Depends:    []*Depend{},
							},
							&Task{
								Name: "task04",
								Runtime: &Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*Container{
										&Container{
											Image: "image01",
										},
									},
								},
								WorkingDir: defaultWorkingDir,
								Steps:      []interface{}{},
								Depends:    []*Depend{},
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
