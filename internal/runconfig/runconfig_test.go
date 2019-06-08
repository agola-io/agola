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

package runconfig

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/sorintlab/agola/internal/config"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/google/go-cmp/cmp"
	errors "golang.org/x/xerrors"
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
			err: fmt.Errorf("circular dependency detected"),
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
			err: fmt.Errorf("circular dependency detected"),
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
			err: fmt.Errorf("circular dependency detected"),
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
							},
						},
					},
					Environment: map[string]string{
						"ENV01":             "ENV01",
						"ENVFROMVARIABLE01": "VARVALUE01",
					},
					Steps: []interface{}{
						&rstypes.RunStep{Step: rstypes.Step{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
						&rstypes.RunStep{Step: rstypes.Step{Type: "run", Name: "name different than command"}, Command: "command02", Environment: map[string]string{}},
						&rstypes.RunStep{Step: rstypes.Step{Type: "run", Name: "command03"}, Command: "command03", Environment: map[string]string{"ENV01": "ENV01", "ENVFROMVARIABLE01": "VARVALUE01"}},
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
							},
						},
					},
					Environment: map[string]string{},
					Steps: []interface{}{
						&rstypes.RunStep{Step: rstypes.Step{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
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
							},
						},
					},
					Environment: map[string]string{},
					Steps: []interface{}{
						&rstypes.RunStep{Step: rstypes.Step{Type: "run", Name: "command01"}, Command: "command01", Environment: map[string]string{}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := GenRunConfigTasks(uuid, tt.in, "run01", tt.variables, "", "", "")

			//if err != nil {
			//	t.Fatalf("unexpected error: %v", err)
			//}
			if diff := cmp.Diff(tt.out, out); diff != "" {
				t.Error(diff)
			}
		})
	}
}
