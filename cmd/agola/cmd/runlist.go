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

	runs := make([]*api.RunResponse, len(runsResp.Runs))
	for i, runsResponse := range runsResp.Runs {
		run, _, err := gwclient.GetRun(context.TODO(), runsResponse.ID)
		if err != nil {
			return err
		}
		runs[i] = run
	}

	printRuns(runs)

	return nil
}
