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
	"sort"

	"agola.io/agola/internal/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdRunList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := runList(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
	Short: "list runs for a specific project or user (direct runs)",
}

type runListOptions struct {
	projectRef  string
	username    string
	phaseFilter []string
	limit       int
	start       uint64
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
	flags.StringVar(&runListOpts.username, "username", "", "User name for user direct runs")
	flags.StringSliceVarP(&runListOpts.phaseFilter, "phase", "s", nil, "filter runs matching the provided phase. This option can be repeated multiple times")
	flags.IntVar(&runListOpts.limit, "limit", 10, "max number of runs to show")
	flags.Uint64Var(&runListOpts.start, "start", 0, "starting run number (excluded) to fetch")

	cmdRun.AddCommand(cmdRunList)
}

func printRuns(runs []*runDetails) {
	for _, run := range runs {
		fmt.Printf("%d: Phase: %s, Result: %s\n", run.runResponse.Number, run.runResponse.Phase, run.runResponse.Result)
		for _, task := range run.tasks {
			fmt.Printf("\tTaskName: %s, TaskID: %s, Status: %s\n", task.runTaskResponse.Name, task.runTaskResponse.ID, task.runTaskResponse.Status)
			if task.retrieveError != nil {
				fmt.Printf("\t\tfailed to retrieve task information: %v\n", task.retrieveError)
			} else {
				for n, step := range task.runTaskResponse.Steps {
					if step.Phase.IsFinished() && step.Type == "run" && step.ExitStatus != nil {
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
	flags := cmd.Flags()

	if flags.Changed("username") && flags.Changed("project") {
		return errors.Errorf(`only one of "--username" or "--project" can be provided`)
	}
	if !flags.Changed("username") && !flags.Changed("project") {
		return errors.Errorf(`one of "--username" or "--project" must be provided`)
	}

	gwclient := gwclient.NewClient(gatewayURL, token)

	isProject := !flags.Changed("username")

	var runsResp []*gwapitypes.RunsResponse
	var err error
	if isProject {
		runsResp, _, err = gwclient.GetProjectRuns(context.TODO(), runListOpts.projectRef, runListOpts.phaseFilter, nil, runListOpts.start, runListOpts.limit, false)
	} else {
		runsResp, _, err = gwclient.GetUserRuns(context.TODO(), runListOpts.username, runListOpts.phaseFilter, nil, runListOpts.start, runListOpts.limit, false)
	}
	if err != nil {
		return errors.WithStack(err)
	}

	runs := make([]*runDetails, len(runsResp))
	for i, runResponse := range runsResp {
		var err error
		var run *gwapitypes.RunResponse
		if isProject {
			run, _, err = gwclient.GetProjectRun(context.TODO(), runListOpts.projectRef, runResponse.Number)
		} else {
			run, _, err = gwclient.GetUserRun(context.TODO(), runListOpts.username, runResponse.Number)
		}
		if err != nil {
			return errors.WithStack(err)
		}

		tasks := []*taskDetails{}
		for _, task := range run.Tasks {
			var runTaskResponse *gwapitypes.RunTaskResponse
			if isProject {
				runTaskResponse, _, err = gwclient.GetUserRunTask(context.TODO(), runListOpts.projectRef, run.Number, task.ID)
			} else {
				runTaskResponse, _, err = gwclient.GetProjectRunTask(context.TODO(), runListOpts.username, run.Number, task.ID)
			}
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
