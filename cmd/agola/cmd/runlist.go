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

package cmd

import (
	"context"
	"fmt"
	"path"
	"sort"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	errors "golang.org/x/xerrors"

	"github.com/spf13/cobra"
)

var cmdRunList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := runList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "list",
}

type runListOptions struct {
	projectRef  string
	phaseFilter []string
	limit       int
	start       string
}

type runDetails struct {
	runResponse *gwapitypes.RunResponse
	tasks       []*taskDetails
}

type taskDetails struct {
	name            string
	level           int
	runTaskResponse *gwapitypes.RunTaskResponse
	retrieveError   error
}

var runListOpts runListOptions

func init() {
	flags := cmdRunList.Flags()

	flags.StringVar(&runListOpts.projectRef, "project", "", "project id or full path")
	flags.StringSliceVarP(&runListOpts.phaseFilter, "phase", "s", nil, "filter runs matching the provided phase. This option can be repeated multiple times")
	flags.IntVar(&runListOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&runListOpts.start, "start", "", "starting run id (excluded) to fetch")

	if err := cmdRunList.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}

	cmdRun.AddCommand(cmdRunList)
}

func printRuns(runs []*runDetails) {
	for _, run := range runs {
		fmt.Printf("%s: Phase: %s, Result: %s\n", run.runResponse.ID, run.runResponse.Phase, run.runResponse.Result)
		for _, task := range run.tasks {
			fmt.Printf("\tTaskName: %s, TaskID: %s, Status: %s\n", task.runTaskResponse.Name, task.runTaskResponse.ID, task.runTaskResponse.Status)
			if task.retrieveError != nil {
				fmt.Printf("\t\tfailed to retrieve task information: %v\n", task.retrieveError)
			} else {
				for n, step := range task.runTaskResponse.Steps {
					if step.Phase.IsFinished() && step.Type == "run" {
						fmt.Printf("\t\tStep: %d, Name: %s, Type: %s, Phase: %s, ExitStatus: %d\n", n, step.Name, step.Type, step.Phase, *step.ExitStatus)
					} else {
						fmt.Printf("\t\tStep: %d, Name: %s, Type: %s, Phase: %s\n", n, step.Name, step.Type, step.Phase)
					}
				}
			}
		}
	}
}

func runList(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	project, _, err := gwclient.GetProject(context.TODO(), runListOpts.projectRef)
	if err != nil {
		return errors.Errorf("failed to get project %s: %v", runListOpts.projectRef, err)
	}
	groups := []string{path.Join("/project", project.ID)}
	runsResp, _, err := gwclient.GetRuns(context.TODO(), runListOpts.phaseFilter, nil, groups, nil, runListOpts.start, runListOpts.limit, false)
	if err != nil {
		return err
	}

	runs := make([]*runDetails, len(runsResp))
	for i, runResponse := range runsResp {
		run, _, err := gwclient.GetRun(context.TODO(), runResponse.ID)
		if err != nil {
			return err
		}

		tasks := []*taskDetails{}
		for _, task := range run.Tasks {
			runTaskResponse, _, err := gwclient.GetRunTask(context.TODO(), run.ID, task.ID)
			t := &taskDetails{
				name:            task.Name,
				level:           task.Level,
				runTaskResponse: runTaskResponse,
				retrieveError:   err,
			}
			tasks = append(tasks, t)
		}

		sort.Slice(tasks, func(i, j int) bool {
			if tasks[i].level != tasks[j].level {
				return tasks[i].level < tasks[j].level
			}
			return tasks[i].name < tasks[j].name
		})

		runs[i] = &runDetails{
			runResponse: run,
			tasks:       tasks,
		}
	}

	printRuns(runs)

	return nil
}
