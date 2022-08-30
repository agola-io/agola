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

package runconfig

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"agola.io/agola/internal/config"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
	rstypes "agola.io/agola/services/runservice/types"
	"agola.io/agola/services/types"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/google/go-cmp/cmp"
)

var uuid = &util.TestUUIDGenerator{}

func TestGenTasksLevels(t *testing.T) {
	type task struct {
		ID      string
		Level   int
		Depends map[string]*rstypes.RunConfigTaskDepend
	}
	tests := []struct {
		name string
		in   []task
		out  []task
		err  error
	}{
		{
			name: "test single task",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
			},
			out: []task{
				{
					ID:    "1",
					Level: 0,
				},
			},
		},
		{
			name: "test multiple root tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
				},
			},
			out: []task{
				{
					ID:    "1",
					Level: 0,
				},
				{
					ID:    "2",
					Level: 0,
				},
			},
		},
		{
			name: "test dependency between two tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			out: []task{
				{
					ID:    "1",
					Level: 0,
				},
				{
					ID:    "2",
					Level: 1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
		},
		{
			name: "Test circular dependency between two tasks: a -> b -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: errors.Errorf("circular dependency detected"),
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: errors.Errorf("circular dependency detected"),
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> b",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
			},
			err: errors.Errorf("circular dependency detected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inRcts := map[string]*rstypes.RunConfigTask{}
			for _, t := range tt.in {
				inRcts[t.ID] = &rstypes.RunConfigTask{
					ID:      t.ID,
					Level:   t.Level,
					Depends: t.Depends,
				}

			}
			outRcts := map[string]*rstypes.RunConfigTask{}
			for _, t := range tt.out {
				outRcts[t.ID] = &rstypes.RunConfigTask{
					ID:      t.ID,
					Level:   t.Level,
					Depends: t.Depends,
				}

			}
			if err := GenTasksLevels(inRcts); err != nil {
				if err.Error() != tt.err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
				return
			}
			if tt.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.err)
			}
			if !reflect.DeepEqual(inRcts, outRcts) {
				t.Fatalf("got %s, expected %s", util.Dump(inRcts), util.Dump(outRcts))
			}
		})
	}
}

func TestGetAllParents(t *testing.T) {
	type task struct {
		ID      string
		Level   int
		Depends map[string]*rstypes.RunConfigTaskDepend
	}
	tests := []struct {
		name string
		in   []task
		out  map[string][]string
	}{
		{
			name: "test single task",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
			},
			out: map[string][]string{
				"1": []string{},
			},
		},
		{
			name: "test multiple root tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
				},
			},
			out: map[string][]string{
				"1": []string{},
				"2": []string{},
			},
		},
		{
			name: "test dependency from a task to itself",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			out: map[string][]string{
				"1": []string{"1"},
			},
		},
		{
			name: "test dependency between two tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			out: map[string][]string{
				"1": []string{},
				"2": []string{"1"},
			},
		},
		{
			name: "Test dependency between 5 tasks: a -> (b, c) -> (d, e)",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"4": &rstypes.RunConfigTaskDepend{TaskID: "4"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"5": &rstypes.RunConfigTaskDepend{TaskID: "5"},
					},
				},
				{
					ID:    "4",
					Level: -1,
				},
				{
					ID:    "5",
					Level: -1,
				},
			},
			out: map[string][]string{
				"1": []string{"2", "3", "4", "5"},
				"2": []string{"4"},
				"3": []string{"5"},
				"4": []string{},
				"5": []string{},
			},
		},
		{
			name: "Test circular dependency between two tasks: a -> b -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			out: map[string][]string{
				"1": []string{"2", "1"},
				"2": []string{"1", "2"},
			},
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			out: map[string][]string{
				"1": []string{"2", "3", "1"},
				"2": []string{"3", "1", "2"},
				"3": []string{"1", "2", "3"},
			},
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> b",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
			},
			out: map[string][]string{
				"1": []string{"2", "3"},
				"2": []string{"3", "2"},
				"3": []string{"2", "3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inRcts := map[string]*rstypes.RunConfigTask{}
			for _, t := range tt.in {
				inRcts[t.ID] = &rstypes.RunConfigTask{
					ID:      t.ID,
					Level:   t.Level,
					Depends: t.Depends,
				}

			}

			for _, task := range inRcts {
				allParents := GetAllParents(inRcts, task)

				allParentsList := []string{}
				for _, p := range allParents {
					allParentsList = append(allParentsList, p.ID)
				}
				if !util.CompareStringSliceNoOrder(tt.out[task.ID], allParentsList) {
					t.Fatalf("task: %s, got %s, expected %s", task.ID, util.Dump(allParentsList), util.Dump(tt.out[task.ID]))
				}
			}
		})
	}
}

func TestCheckRunConfig(t *testing.T) {
	type task struct {
		ID      string
		Level   int
		Depends map[string]*rstypes.RunConfigTaskDepend
	}
	tests := []struct {
		name string
		in   []task
		err  error
	}{
		{
			name: "test single task",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
			},
		},
		{
			name: "test multiple root tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
				},
			},
		},
		{
			name: "test dependency between two tasks",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
		},
		{
			name: "Test circular dependency between two tasks: a -> b -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: &util.Errors{
				Errs: []error{
					errors.Errorf("circular dependency between task %q and tasks %q", "task1", "task2"),
					errors.Errorf("circular dependency between task %q and tasks %q", "task2", "task1"),
				},
			},
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> a",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: &util.Errors{
				Errs: []error{
					errors.Errorf("circular dependency between task %q and tasks %q", "task1", "task3"),
					errors.Errorf("circular dependency between task %q and tasks %q", "task2", "task1"),
					errors.Errorf("circular dependency between task %q and tasks %q", "task3", "task2"),
				},
			},
		},
		{
			name: "Test circular dependency between 3 tasks: a -> b -> c -> b",
			in: []task{
				{
					ID:    "1",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
			},
			err: &util.Errors{
				Errs: []error{
					errors.Errorf("circular dependency between task %q and tasks %q", "task2", "task3"),
					errors.Errorf("circular dependency between task %q and tasks %q", "task3", "task2"),
				},
			},
		},
		{
			name: "test task parent same dep a -> b -> c, a -> c",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: errors.Errorf("task %q and its parent %q have both a dependency on task %q", "task3", "task2", "task1"),
		},
		{
			name: "test task parent same dep a -> b -> c -> d, a -> d",
			in: []task{
				{
					ID:    "1",
					Level: -1,
				},
				{
					ID:    "2",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
				{
					ID:    "3",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"2": &rstypes.RunConfigTaskDepend{TaskID: "2"},
					},
				},
				{
					ID:    "4",
					Level: -1,
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						"3": &rstypes.RunConfigTaskDepend{TaskID: "3"},
						"1": &rstypes.RunConfigTaskDepend{TaskID: "1"},
					},
				},
			},
			err: errors.Errorf("task %q and its parent %q have both a dependency on task %q", "task4", "task3", "task1"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inRcts := map[string]*rstypes.RunConfigTask{}
			for _, t := range tt.in {
				inRcts[t.ID] = &rstypes.RunConfigTask{
					Name:    fmt.Sprintf("task%s", t.ID),
					ID:      t.ID,
					Level:   t.Level,
					Depends: t.Depends,
				}

			}

			if err := CheckRunConfigTasks(inRcts); err != nil {
				var errs *util.Errors
				if errors.As(err, &errs) {
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

func TestGenRunConfig(t *testing.T) {
	tests := []struct {
		name      string
		in        *config.Config
		variables map[string]string
		out       map[string]*rstypes.RunConfigTask
	}{
		{
			name: "test runconfig generation",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type:     config.DockerRegistryAuthTypeBasic,
								Username: config.Value{Type: config.ValueTypeString, Value: "username"},
								Password: config.Value{Type: config.ValueTypeFromVariable, Value: "password"},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
									"index.docker.io": {
										Type:     config.DockerRegistryAuthTypeBasic,
										Username: config.Value{Type: config.ValueTypeFromVariable, Value: "registry_username"},
										Password: config.Value{Type: config.ValueTypeString, Value: "password2"},
									},
								},
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
											Environment: map[string]config.Value{
												"ENV01":             config.Value{Type: config.ValueTypeString, Value: "ENV01"},
												"ENVFROMVARIABLE01": config.Value{Type: config.ValueTypeFromVariable, Value: "variable01"},
											},
											User: "",
											Volumes: []config.Volume{
												config.Volume{
													Path:  "/mnt/vol01",
													TmpFS: &config.VolumeTmpFS{},
												},
												config.Volume{
													Path:  "/mnt/vol01",
													TmpFS: &config.VolumeTmpFS{Size: resource.NewQuantity(1024*1024*1024, resource.BinarySI)},
												},
											},
										},
									},
								},
								Environment: map[string]config.Value{
									"ENV01":             config.Value{Type: config.ValueTypeString, Value: "ENV01"},
									"ENVFROMVARIABLE01": config.Value{Type: config.ValueTypeFromVariable, Value: "variable01"},
								},
								WorkingDir: "",
								Shell:      "",
								User:       "",
								Steps: config.Steps{
									&config.RunStep{
										BaseStep: config.BaseStep{
											Type: "run",
											Name: "command01",
										},
										Command: "command01",
									},
									&config.RunStep{
										BaseStep: config.BaseStep{
											Type: "run",
											Name: "name different than command",
										},
										Command: "command02",
									},
									&config.RunStep{
										BaseStep: config.BaseStep{
											Type: "run",
											Name: "command03",
										},
										Command: "command03",
										Environment: map[string]config.Value{
											"ENV01":             config.Value{Type: config.ValueTypeString, Value: "ENV01"},
											"ENVFROMVARIABLE01": config.Value{Type: config.ValueTypeFromVariable, Value: "variable01"},
										},
									},
								},

								Depends:       []*config.Depend{},
								IgnoreFailure: false,
								Approval:      false,
								When: &config.When{
									Branch: &types.WhenConditions{Include: []types.WhenCondition{{Match: "master"}}},
									Tag:    &types.WhenConditions{Include: []types.WhenCondition{{Match: "v1.x"}, {Match: "v2.x"}}},
									Ref: &types.WhenConditions{
										Include: []types.WhenCondition{{Match: "master"}},
										Exclude: []types.WhenCondition{{Match: "branch01", Type: types.WhenConditionTypeRegExp}, {Match: "branch02"}},
									},
								},
							},
						},
					},
				},
			},
			variables: map[string]string{
				"variable01":        "VARVALUE01",
				"registry_username": "yourregistryusername",
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type:     rstypes.DockerRegistryAuthTypeBasic,
							Username: "yourregistryusername",
							Password: "password2",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image: "image01",
								Environment: map[string]string{
									"ENV01":             "ENV01",
									"ENVFROMVARIABLE01": "VARVALUE01",
								},
								Volumes: []rstypes.Volume{
									rstypes.Volume{
										Path:  "/mnt/vol01",
										TmpFS: &rstypes.VolumeTmpFS{},
									},
									rstypes.Volume{
										Path:  "/mnt/vol01",
										TmpFS: &rstypes.VolumeTmpFS{Size: 1024 * 1024 * 1024},
									},
								},
							},
						},
					},
					Shell: "/bin/sh -e",
					Environment: map[string]string{
						"ENV01":             "ENV01",
						"ENVFROMVARIABLE01": "VARVALUE01",
					},
					Steps: rstypes.Steps{
						&rstypes.RunStep{BaseStep: rstypes.BaseStep{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
						&rstypes.RunStep{BaseStep: rstypes.BaseStep{Type: "run", Name: "name different than command"}, Command: "command02", Environment: map[string]string{}},
						&rstypes.RunStep{BaseStep: rstypes.BaseStep{Type: "run", Name: "command03"}, Command: "command03", Environment: map[string]string{"ENV01": "ENV01", "ENVFROMVARIABLE01": "VARVALUE01"}},
					},
					Skip: true,
				},
			},
		},
		{
			name: "test run auth used for task undefined auth",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type:     config.DockerRegistryAuthTypeBasic,
								Username: config.Value{Type: config.ValueTypeString, Value: "username"},
								Password: config.Value{Type: config.ValueTypeFromVariable, Value: "password"},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},
								Steps: config.Steps{
									&config.RunStep{
										BaseStep: config.BaseStep{
											Type: "run",
											Name: "command01",
										},
										Command: "command01",
									},
								},
							},
						},
					},
				},
			},
			variables: map[string]string{
				"variable01": "VARVALUE01",
				"password":   "yourregistrypassword",
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type:     rstypes.DockerRegistryAuthTypeBasic,
							Username: "username",
							Password: "yourregistrypassword",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Environment: map[string]string{},
								Volumes:     []rstypes.Volume{},
							},
						},
					},
					Shell:       "/bin/sh -e",
					Environment: map[string]string{},
					Steps: rstypes.Steps{
						&rstypes.RunStep{BaseStep: rstypes.BaseStep{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
					},
				},
			},
		},
		{
			name: "test run auth override by task auth",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type:     config.DockerRegistryAuthTypeBasic,
								Username: config.Value{Type: config.ValueTypeString, Value: "username"},
								Password: config.Value{Type: config.ValueTypeFromVariable, Value: "password"},
							},
							"https://myregistry.example.com": {
								Type:     config.DockerRegistryAuthTypeBasic,
								Username: config.Value{Type: config.ValueTypeString, Value: "username"},
								Password: config.Value{Type: config.ValueTypeFromVariable, Value: "password"},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
									"index.docker.io": {
										Type:     config.DockerRegistryAuthTypeBasic,
										Username: config.Value{Type: config.ValueTypeFromVariable, Value: "registry_username"},
										Password: config.Value{Type: config.ValueTypeString, Value: "password2"},
									},
									"https://anotherregistry.example.com": {
										Type:     config.DockerRegistryAuthTypeBasic,
										Username: config.Value{Type: config.ValueTypeFromVariable, Value: "registry_username"},
										Password: config.Value{Type: config.ValueTypeString, Value: "password2"},
									},
								},
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},
								Steps: config.Steps{
									&config.RunStep{
										BaseStep: config.BaseStep{
											Type: "run",
											Name: "command01",
										},
										Command: "command01",
									},
								},
							},
						},
					},
				},
			},
			variables: map[string]string{
				"variable01":        "VARVALUE01",
				"registry_username": "yourregistryusername",
				"password":          "myregistrypassword",
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type:     rstypes.DockerRegistryAuthTypeBasic,
							Username: "yourregistryusername",
							Password: "password2",
						},
						"https://myregistry.example.com": {
							Type:     rstypes.DockerRegistryAuthTypeBasic,
							Username: "username",
							Password: "myregistrypassword",
						},
						"https://anotherregistry.example.com": {
							Type:     rstypes.DockerRegistryAuthTypeBasic,
							Username: "yourregistryusername",
							Password: "password2",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Environment: map[string]string{},
								Volumes:     []rstypes.Volume{},
							},
						},
					},
					Shell:       "/bin/sh -e",
					Environment: map[string]string{},
					Steps: rstypes.Steps{
						&rstypes.RunStep{BaseStep: rstypes.BaseStep{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
					},
				},
			},
		},
		{
			name: "test run task depends on_skipped",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},
							},
							&config.Task{
								Name: "task02",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},
								Depends: config.Depends{
									&config.Depend{
										TaskName: "task01",
										Conditions: []config.DependCondition{
											config.DependConditionOnSkipped,
										},
									},
								},
							},
						},
					},
				},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Environment: map[string]string{},
								Volumes:     []rstypes.Volume{},
							},
						},
					},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{},
					Shell:                "/bin/sh -e",
					Environment:          map[string]string{},
					Steps:                rstypes.Steps{},
				},
				uuid.New("task02").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task02").String(),
					Name: "task02",
					Depends: map[string]*rstypes.RunConfigTaskDepend{
						uuid.New("task01").String(): &rstypes.RunConfigTaskDepend{
							TaskID:     uuid.New("task01").String(),
							Conditions: []rstypes.RunConfigTaskDependCondition{rstypes.RunConfigTaskDependConditionOnSkipped},
						},
					},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Environment: map[string]string{},
								Volumes:     []rstypes.Volume{},
							},
						},
					},
					Shell:       "/bin/sh -e",
					Environment: map[string]string{},
					Steps:       rstypes.Steps{},
				},
			},
		},
		{
			name: "test runconfig generation encodedauth global",
			in: &config.Config{
				DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
					"index.docker.io": {
						Type: config.DockerRegistryAuthTypeEncodedAuth,
						Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWU6cGFzc3dvcmQ="},
					},
				},
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
					},
				},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type: rstypes.DockerRegistryAuthTypeEncodedAuth,
							Auth: "dXNlcm5hbWU6cGFzc3dvcmQ=",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
		{
			name: "test global encodedauth override by run auth",
			in: &config.Config{
				DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
					"index.docker.io": {
						Type: config.DockerRegistryAuthTypeEncodedAuth,
						Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWU6cGFzc3dvcmQy"},
					},
				},
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type: config.DockerRegistryAuthTypeEncodedAuth,
								Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWUxOnBhc3N3b3JkMQ=="},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
					},
				},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type: rstypes.DockerRegistryAuthTypeEncodedAuth,
							Auth: "dXNlcm5hbWUxOnBhc3N3b3JkMQ==",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
		{
			name: "test global run encodedauth override by task auth",
			in: &config.Config{
				DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
					"index.docker.io": {
						Type: config.DockerRegistryAuthTypeEncodedAuth,
						Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWU6cGFzc3dvcmQy"},
					},
				},
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type: config.DockerRegistryAuthTypeEncodedAuth,
								Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWUxOnBhc3N3b3JkMQ=="},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
									"index.docker.io": {
										Type: config.DockerRegistryAuthTypeEncodedAuth,
										Auth: config.Value{Type: config.ValueTypeString, Value: "dXNlcm5hbWUyOnBhc3N3b3JkMg=="},
									},
								},
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
					},
				},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type: rstypes.DockerRegistryAuthTypeEncodedAuth,
							Auth: "dXNlcm5hbWUyOnBhc3N3b3JkMg==",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
		{
			name: "test runconfig generation with encoded value type",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
							"index.docker.io": {
								Type: config.DockerRegistryAuthTypeEncodedAuth,
								Auth: config.Value{Type: config.ValueTypeString, Value: "yourregistryusername:password2"},
							},
						},
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								DockerRegistriesAuth: map[string]*config.DockerRegistryAuth{
									"index.docker.io": {
										Type: config.DockerRegistryAuthTypeEncodedAuth,
										Auth: config.Value{Type: config.ValueTypeFromVariable, Value: "auth"},
									},
								},
								Runtime: &config.Runtime{
									Type: "pod",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
											User:  "",
										},
									},
								},
								Depends:       []*config.Depend{},
								IgnoreFailure: false,
								Approval:      false,
							},
						},
					},
				},
			},
			variables: map[string]string{
				"auth": "eW91cnJlZ2lzdHJ5dXNlcm5hbWU6cGFzc3dvcmQy",
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{
						"index.docker.io": {
							Type: rstypes.DockerRegistryAuthTypeEncodedAuth,
							Auth: "eW91cnJlZ2lzdHJ5dXNlcm5hbWU6cGFzc3dvcmQy",
						},
					},
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Environment: map[string]string{},
								Volumes:     []rstypes.Volume{},
							},
						},
					},
					Shell:       "/bin/sh -e",
					Environment: map[string]string{},
					Steps:       rstypes.Steps{},
					Skip:        false,
				},
			},
		},
		{
			name: "test runconfig generation task timeout global",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
					},
				},
				TaskTimeoutInterval: &types.Duration{Duration: 10 * time.Second},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{},
					TaskTimeoutInterval:  10 * time.Second,
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
		{
			name: "test global task timeout override by run",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						Tasks: []*config.Task{
							&config.Task{
								Name: "task01",
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
						TaskTimeoutInterval: &types.Duration{Duration: 15 * time.Second},
					},
				},
				TaskTimeoutInterval: &types.Duration{Duration: 10 * time.Second},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{},
					TaskTimeoutInterval:  15 * time.Second,
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
		{
			name: "test global task timeout override by task",
			in: &config.Config{
				Runs: []*config.Run{
					&config.Run{
						Name: "run01",
						Tasks: []*config.Task{
							&config.Task{
								Name:                "task01",
								TaskTimeoutInterval: &types.Duration{Duration: 20 * time.Second},
								Runtime: &config.Runtime{
									Type: "pod",
									Arch: "",
									Containers: []*config.Container{
										&config.Container{
											Image: "image01",
										},
									},
								},

								Depends:    []*config.Depend{},
								WorkingDir: "",
								Shell:      "",
								User:       "",
							},
						},
						TaskTimeoutInterval: &types.Duration{Duration: 15 * time.Second},
					},
				},
				TaskTimeoutInterval: &types.Duration{Duration: 10 * time.Second},
			},
			out: map[string]*rstypes.RunConfigTask{
				uuid.New("task01").String(): &rstypes.RunConfigTask{
					ID:   uuid.New("task01").String(),
					Name: "task01", Depends: map[string]*rstypes.RunConfigTaskDepend{},
					DockerRegistriesAuth: map[string]rstypes.DockerRegistryAuth{},
					TaskTimeoutInterval:  20 * time.Second,
					Runtime: &rstypes.Runtime{Type: rstypes.RuntimeType("pod"),
						Containers: []*rstypes.Container{
							{
								Image:       "image01",
								Volumes:     []rstypes.Volume{},
								Environment: map[string]string{},
							},
						},
					},
					Environment: map[string]string{},
					Skip:        false,
					Steps:       rstypes.Steps{},
					Shell:       "/bin/sh -e",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := GenRunConfigTasks(uuid, tt.in, "run01", tt.variables, "", "", "", "")

			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}
