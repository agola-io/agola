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

	"agola.io/agola/internal/util"
	"agola.io/agola/services/types"

	"github.com/google/go-cmp/cmp"
	errors "golang.org/x/xerrors"
	"k8s.io/apimachinery/pkg/api/resource"
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
			name: "test empty runtime arch",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                `,
		},
		{
			name: "test invalid runtime arch",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          arch: invalidarch
                          containers:
                            - image: busybox
                `,
			err: fmt.Errorf(`task "task01" runtime: invalid arch "invalidarch"`),
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
		{
			name: "test task parent same dep a -> b -> c, a -> c",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                      - name: task02
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task01
                      - name: task03
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task02
                          - task01
                `,
			err: errors.Errorf("task %q and its dependency %q have both a dependency on task %q", "task03", "task02", "task01"),
		},
		{
			name: "test task parent same dep a -> b -> c -> d, a -> d",
			in: `
                runs:
                  - name: run01
                    tasks:
                      - name: task01
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                      - name: task02
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task01
                      - name: task03
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task02
                      - name: task04
                        runtime:
                          type: pod
                          containers:
                            - image: busybox
                        depends:
                          - task03
                          - task01
                `,
			err: errors.Errorf("task %q and its dependency %q have both a dependency on task %q", "task04", "task03", "task01"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.in), ConfigFormatJSON, &ConfigContext{}); err != nil {
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
                    docker_registries_auth:
                      index.docker.io:
                        username: username
                        password:
                          from_variable: password
                    tasks:
                      - name: task01
                        docker_registries_auth:
                          index.docker.io:
                            username: username
                            password:
                              from_variable: password
                        runtime:
                          type: pod
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
                              volumes:
                                - path: /mnt/tmpfs
                                  tmpfs:
                                    size: 1Gi
                      - name: task04
                        runtime:
                          type: pod
                          containers:
                            - image: image01
                              volumes:
                                - path: /mnt/tmpfs
                                  tmpfs: {}
                      - name: task05
                        runtime:
                          type: pod
                          containers:
                            - image: image01
                        steps:
                          - type: run
                            name: command with default tty
                            command: command01
                          - type: run
                            name: command with tty as true
                            command: command02
                            tty: true
                          - type: run
                            name: command with tty as false
                            command: command03
                            tty: false
          `,
			out: &Config{
				Runs: []*Run{
					&Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*DockerRegistryAuth{
							"index.docker.io": {
								Type:     DockerRegistryAuthTypeBasic,
								Username: Value{Type: ValueTypeString, Value: "username"},
								Password: Value{Type: ValueTypeFromVariable, Value: "password"},
							},
						},
						Tasks: []*Task{
							&Task{
								Name: "task01",
								DockerRegistriesAuth: map[string]*DockerRegistryAuth{
									"index.docker.io": {
										Type:     DockerRegistryAuthTypeBasic,
										Username: Value{Type: ValueTypeString, Value: "username"},
										Password: Value{Type: ValueTypeFromVariable, Value: "password"},
									},
								},
								Runtime: &Runtime{
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
								Environment: map[string]Value{
									"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
									"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
								},
								WorkingDir: defaultWorkingDir,
								Shell:      "",
								User:       "",
								Steps: Steps{
									&CloneStep{BaseStep: BaseStep{Type: "clone"}},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command01",
										},
										Command: "command01",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "name different than command",
										},
										Command: "command02",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command03",
										},
										Command: "command03",
										Environment: map[string]Value{
											"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
											"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
										},
										Tty: util.BoolP(true),
									},
									&SaveCacheStep{
										BaseStep: BaseStep{Type: "save_cache"},
										Key:      "cache-{{ arch }}",
										Contents: []*SaveContent{&SaveContent{SourceDir: "/go/pkg/mod/cache", Paths: []string{"**"}}},
									},
									&CloneStep{BaseStep: BaseStep{Type: "clone"}},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command01",
										},
										Command: "command01",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "name different than command",
										},
										Command: "command02",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command03",
										},
										Command: "command03",
										Environment: map[string]Value{
											"ENV01":             Value{Type: ValueTypeString, Value: "ENV01"},
											"ENVFROMVARIABLE01": Value{Type: ValueTypeFromVariable, Value: "variable01"},
										},
										Tty: util.BoolP(true),
									},
									&SaveCacheStep{
										BaseStep: BaseStep{Type: "save_cache"},
										Key:      "cache-{{ arch }}",
										Contents: []*SaveContent{&SaveContent{SourceDir: "/go/pkg/mod/cache", Paths: []string{"**"}}},
									},
								},
								IgnoreFailure: false,
								Approval:      false,
								When: &When{
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
								Steps:      nil,
								Depends:    nil,
							},
							&Task{
								Name: "task03",
								Runtime: &Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*Container{
										&Container{
											Image:   "image01",
											Volumes: []Volume{{Path: "/mnt/tmpfs", TmpFS: &VolumeTmpFS{Size: resource.NewQuantity(1024*1024*1024, resource.BinarySI)}}},
										},
									},
								},
								WorkingDir: defaultWorkingDir,
								Steps:      nil,
								Depends:    nil,
							},
							&Task{
								Name: "task04",
								Runtime: &Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*Container{
										&Container{
											Image:   "image01",
											Volumes: []Volume{{Path: "/mnt/tmpfs", TmpFS: &VolumeTmpFS{}}},
										},
									},
								},
								WorkingDir: defaultWorkingDir,
								Steps:      nil,
								Depends:    nil,
							},
							&Task{
								Name: "task05",
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
								Steps: Steps{
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command with default tty",
										},
										Command: "command01",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command with tty as true",
										},
										Command: "command02",
										Tty:     util.BoolP(true),
									},
									&RunStep{
										BaseStep: BaseStep{
											Type: "run",
											Name: "command with tty as false",
										},
										Command: "command03",
										Tty:     util.BoolP(false),
									},
								},
								Depends: nil,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ParseConfig([]byte(tt.in), ConfigFormatJSON, &ConfigContext{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.out, out, cmp.Comparer(func(x, y *resource.Quantity) bool {
				if x == nil && y == nil {
					return true
				}
				if x != nil && y != nil {
					return x.Cmp(*y) == 0
				}

				return false
			})); diff != "" {
				t.Error(diff)
			}
		})
	}
}
