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
	"net/http"
	"os"

	"agola.io/agola/internal/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdLogGet = &cobra.Command{
	Use:   "get",
	Short: "get a setup/step log",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logGet(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type logGetOptions struct {
	projectRef string
	username   string
	runNumber  uint64
	taskname   string
	taskid     string
	step       int
	setup      bool
	follow     bool
	output     string
}

var logGetOpts logGetOptions

func init() {
	flags := cmdLogGet.Flags()

	flags.StringVar(&logGetOpts.projectRef, "project", "", "project id or full path")
	flags.StringVar(&logGetOpts.username, "username", "", "user name for user direct runs")
	flags.Uint64Var(&logGetOpts.runNumber, "runnumber", 0, "run number")
	flags.StringVar(&logGetOpts.taskname, "taskname", "", "Task name")
	flags.StringVar(&logGetOpts.taskid, "taskid", "", "Task Id")
	flags.IntVar(&logGetOpts.step, "step", 0, "Step number")
	flags.BoolVar(&logGetOpts.setup, "setup", false, "Setup step")
	flags.BoolVar(&logGetOpts.follow, "follow", false, "Follow log stream")
	flags.StringVar(&logGetOpts.output, "output", "", "Write output to file")

	if err := cmdLogGet.MarkFlagRequired("runnumber"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdLog.AddCommand(cmdLogGet)
}

func logGet(cmd *cobra.Command, args []string) error {
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
	if flags.Changed("step") && logGetOpts.step < 0 {
		return errors.Errorf("step number %d is invalid, it must be equal or greater than zero", logGetOpts.step)
	}
	if flags.Changed("follow") && flags.Changed("output") {
		return errors.Errorf(`only one of "--follow" or "--output" can be provided`)
	}

	gwclient := gwclient.NewClient(gatewayURL, token)

	isProject := !flags.Changed("username")

	if flags.Changed("taskid") {
		taskid = logGetOpts.taskid
	}
	if flags.Changed("taskname") {
		var task *gwapitypes.RunResponseTask
		var taskfound bool

		var run *gwapitypes.RunResponse
		var err error
		if isProject {
			run, _, err = gwclient.GetProjectRun(context.TODO(), logGetOpts.projectRef, logGetOpts.runNumber)
		} else {
			run, _, err = gwclient.GetUserRun(context.TODO(), logGetOpts.username, logGetOpts.runNumber)
		}
		if err != nil {
			return errors.WithStack(err)
		}

		for _, t := range run.Tasks {
			if t.Name == logGetOpts.taskname {
				task = t
				taskfound = true
				break
			}
		}
		if !taskfound {
			return errors.Errorf("task %q not found in run %q", logGetOpts.taskname, logGetOpts.runNumber)
		}
		taskid = task.ID
	}

	log.Info().Msgf("getting log")

	var resp *http.Response
	var err error
	if isProject {
		resp, err = gwclient.GetProjectLogs(context.TODO(), logGetOpts.projectRef, logGetOpts.runNumber, taskid, logGetOpts.setup, logGetOpts.step, logGetOpts.follow)
	} else {
		resp, err = gwclient.GetUserLogs(context.TODO(), logGetOpts.username, logGetOpts.runNumber, taskid, logGetOpts.setup, logGetOpts.step, logGetOpts.follow)
	}
	if err != nil {
		return errors.Errorf("failed to get log: %v", err)
	}
	defer resp.Body.Close()

	if flags.Changed("output") {
		f, err := os.Create(logGetOpts.output)
		if err != nil {
			return errors.WithStack(err)
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
