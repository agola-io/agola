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

	"github.com/sorintlab/agola/internal/services/gateway/api"

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
	statusFilter []string
	labelFilter  []string
	limit        int
	start        string
}

var runListOpts runListOptions

func init() {
	flags := cmdRunList.PersistentFlags()

	flags.StringSliceVarP(&runListOpts.statusFilter, "status", "s", nil, "filter runs matching the provided status. This option can be repeated multiple times")
	flags.StringArrayVarP(&runListOpts.labelFilter, "label", "l", nil, "filter runs matching the provided label. This option can be repeated multiple times, in this case only runs matching all the labels will be returned")
	flags.IntVar(&runListOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&runListOpts.start, "start", "", "starting run id (excluded) to fetch")

	cmdRun.AddCommand(cmdRunList)
}

func printRuns(runs []*api.RunResponse) {
	for _, run := range runs {
		fmt.Printf("%s: Phase: %s, Result: %s\n", run.ID, run.Phase, run.Result)
		for _, task := range run.Tasks {
			fmt.Printf("\tTaskName: %s, Status: %s\n", task.Name, task.Status)
		}
	}
}

func runList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	runsResp, _, err := gwclient.GetRuns(context.TODO(), runListOpts.statusFilter, runListOpts.labelFilter, []string{}, runListOpts.start, runListOpts.limit, false)
	if err != nil {
		return err
	}

	runs := make([]*api.RunResponse, len(runsResp))
	for i, runResponse := range runsResp {
		run, _, err := gwclient.GetRun(context.TODO(), runResponse.ID)
		if err != nil {
			return err
		}
		runs[i] = run
	}

	printRuns(runs)

	return nil
}
