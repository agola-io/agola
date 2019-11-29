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

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdLogDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a setup/step log",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type logDeleteOptions struct {
	runid    string
	taskname string
	taskid   string
	step     int
	setup    bool
}

var logDeleteOpts logDeleteOptions

func init() {
	flags := cmdLogDelete.Flags()

	flags.StringVar(&logDeleteOpts.runid, "runid", "", "Run Id")
	flags.StringVar(&logDeleteOpts.taskname, "taskname", "", "Task name")
	flags.StringVar(&logDeleteOpts.taskid, "taskid", "", "Task Id")
	flags.IntVar(&logDeleteOpts.step, "step", 0, "Step number")
	flags.BoolVar(&logDeleteOpts.setup, "setup", false, "Setup step")

	if err := cmdLogDelete.MarkFlagRequired("runid"); err != nil {
		log.Fatal(err)
	}

	cmdLog.AddCommand(cmdLogDelete)
}

func logDelete(cmd *cobra.Command, args []string) error {

	var taskid string
	flags := cmd.Flags()

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

	if flags.Changed("taskid") {
		taskid = logDeleteOpts.taskid
	}
	if flags.Changed("taskname") {
		var task *gwapitypes.RunResponseTask
		var taskfound bool

		run, _, err := gwclient.GetRun(context.TODO(), logDeleteOpts.runid)
		if err != nil {
			return err
		}
		for _, t := range run.Tasks {
			if t.Name == logDeleteOpts.taskname {
				task = t
				taskfound = true
				break
			}
		}
		if !taskfound {
			return errors.Errorf("task %q not found in run %q", logDeleteOpts.taskname, logDeleteOpts.runid)
		}
		taskid = task.ID
	}
	log.Infof("deleting log")
	if _, err := gwclient.DeleteLogs(context.TODO(), logDeleteOpts.runid, taskid, logDeleteOpts.setup, logDeleteOpts.step); err != nil {
		return errors.Errorf("failed to delete log: %v", err)
	}

	return nil
}
