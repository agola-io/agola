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

	"agola.io/agola/internal/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdLogDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a setup/step log",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logDelete(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type logDeleteOptions struct {
	projectRef string
	username   string
	runNumber  uint64
	taskname   string
	taskid     string
	step       int
	setup      bool
}

var logDeleteOpts logDeleteOptions

func init() {
	flags := cmdLogDelete.Flags()

	flags.StringVar(&logDeleteOpts.projectRef, "project", "", "project id or full path")
	flags.StringVar(&logDeleteOpts.username, "username", "", "user name for user direct runs")
	flags.Uint64Var(&logDeleteOpts.runNumber, "runnumber", 0, "run number")
	flags.StringVar(&logDeleteOpts.taskname, "taskname", "", "Task name")
	flags.StringVar(&logDeleteOpts.taskid, "taskid", "", "Task Id")
	flags.IntVar(&logDeleteOpts.step, "step", 0, "Step number")
	flags.BoolVar(&logDeleteOpts.setup, "setup", false, "Setup step")

	if err := cmdLogDelete.MarkFlagRequired("runnumber"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdLog.AddCommand(cmdLogDelete)
}

func logDelete(cmd *cobra.Command, args []string) error {
	var taskid string

	flags := cmd.Flags()

	if flags.Changed("username") && flags.Changed("project") {
		return errors.Errorf(`only one of "--username" or "--project" can be provided`)
	}
	if flags.Changed("taskname") && flags.Changed("taskid") {
		return errors.Errorf(`only one of "--taskname" or "--taskid" can be provided`)
	}
	if !flags.Changed("taskname") && !flags.Changed("taskid") {
		return errors.Errorf(`one of "--taskname" or "--taskid" must be provided`)
	}
	if flags.Changed("step") && flags.Changed("setup") {
		return errors.Errorf(`only one of "--step" or "--setup" can be provided`)
	}
	if !flags.Changed("step") && !flags.Changed("setup") {
		return errors.Errorf(`one of "--step" or "--setup" must be provided`)
	}
	if flags.Changed("step") && logDeleteOpts.step < 0 {
		return errors.Errorf("%d is an invalid step number, it must be equal or greater than zero", logDeleteOpts.step)
	}

	gwclient := gwclient.NewClient(gatewayURL, token)

	isProject := !flags.Changed("username")

	if flags.Changed("taskid") {
		taskid = logDeleteOpts.taskid
	}
	if flags.Changed("taskname") {
		var task *gwapitypes.RunResponseTask
		var taskfound bool

		var run *gwapitypes.RunResponse
		var err error
		if isProject {
			run, _, err = gwclient.GetProjectRun(context.TODO(), logDeleteOpts.projectRef, logDeleteOpts.runNumber)
		} else {
			run, _, err = gwclient.GetUserRun(context.TODO(), logDeleteOpts.username, logDeleteOpts.runNumber)
		}
		if err != nil {
			return errors.WithStack(err)
		}
		for _, t := range run.Tasks {
			if t.Name == logDeleteOpts.taskname {
				task = t
				taskfound = true
				break
			}
		}
		if !taskfound {
			return errors.Errorf("task %q not found in run %q", logDeleteOpts.taskname, logDeleteOpts.runNumber)
		}
		taskid = task.ID
	}

	log.Info().Msgf("deleting log")

	var err error
	if isProject {
		_, err = gwclient.DeleteProjectLogs(context.TODO(), logDeleteOpts.projectRef, logDeleteOpts.runNumber, taskid, logDeleteOpts.setup, logDeleteOpts.step)
	} else {
		_, err = gwclient.DeleteUserLogs(context.TODO(), logDeleteOpts.username, logDeleteOpts.runNumber, taskid, logDeleteOpts.setup, logDeleteOpts.step)
	}

	if err != nil {
		return errors.Errorf("failed to delete log: %v", err)
	}

	return nil
}
