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
	"io"
	"os"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdLogGet = &cobra.Command{
	Use:   "get",
	Short: "get a setup/step log",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logGet(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type logGetOptions struct {
	runid    string
	taskname string
	taskid   string
	step     int
	setup    bool
	follow   bool
	output   string
}

var logGetOpts logGetOptions

func init() {
	flags := cmdLogGet.Flags()

	flags.StringVar(&logGetOpts.runid, "runid", "", "Run Id")
	flags.StringVar(&logGetOpts.taskname, "taskname", "", "Task name")
	flags.StringVar(&logGetOpts.taskid, "taskid", "", "Task Id")
	flags.IntVar(&logGetOpts.step, "step", 0, "Step number")
	flags.BoolVar(&logGetOpts.setup, "setup", false, "Setup step")
	flags.BoolVar(&logGetOpts.follow, "follow", false, "Follow log stream")
	flags.StringVar(&logGetOpts.output, "output", "", "Write output to file")

	if err := cmdLogGet.MarkFlagRequired("runid"); err != nil {
		log.Fatal(err)
	}

	cmdLog.AddCommand(cmdLogGet)
}

func logGet(cmd *cobra.Command, args []string) error {

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
	if flags.Changed("step") && logGetOpts.step < 0 {
		return errors.Errorf("step number %d is invalid, it must be equal or greater than zero", logGetOpts.step)
	}
	if flags.Changed("follow") && flags.Changed("output") {
		return errors.Errorf(`only one of "--follow" or "--output" can be provided`)
	}

	gwclient := gwclient.NewClient(gatewayURL, token)

	if flags.Changed("taskid") {
		taskid = logGetOpts.taskid
	}
	if flags.Changed("taskname") {
		var task *gwapitypes.RunResponseTask
		var taskfound bool

		run, _, err := gwclient.GetRun(context.TODO(), logGetOpts.runid)
		if err != nil {
			return err
		}
		for _, t := range run.Tasks {
			if t.Name == logGetOpts.taskname {
				task = t
				taskfound = true
				break
			}
		}
		if !taskfound {
			return errors.Errorf("task %q not found in run %q", logGetOpts.taskname, logGetOpts.runid)
		}
		taskid = task.ID
	}

	log.Infof("getting log")
	resp, err := gwclient.GetLogs(context.TODO(), logGetOpts.runid, taskid, logGetOpts.setup, logGetOpts.step, logGetOpts.follow)
	if err != nil {
		return errors.Errorf("failed to get log: %v", err)
	}
	defer resp.Body.Close()

	if flags.Changed("output") {
		f, err := os.Create(logGetOpts.output)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(f, resp.Body); err != nil {
			return errors.Errorf("failed to write log: %v", err)
		}
	} else {
		if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
			return errors.Errorf("unexpected err: %v", err)
		}
	}

	return nil
}
