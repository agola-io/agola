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
	gitsave "github.com/sorintlab/agola/internal/git-save"

	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
)

var cmdLocalRunStart = &cobra.Command{
	Use: "start",
	Run: func(cmd *cobra.Command, args []string) {
		if err := localRunStart(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "executes a run from a local repository",
}

type localRunStartOptions struct {
	statusFilter []string
	labelFilter  []string
	limit        int
	start        string
	untracked    bool
	ignored      bool
}

var localRunStartOpts localRunStartOptions

func init() {
	flags := cmdLocalRunStart.PersistentFlags()

	flags.StringSliceVarP(&localRunStartOpts.statusFilter, "status", "s", nil, "filter runs matching the provided status. This option can be repeated multiple times")
	flags.StringArrayVarP(&localRunStartOpts.labelFilter, "label", "l", nil, "filter runs matching the provided label. This option can be repeated multiple times, in this case only runs matching all the labels will be returned")
	flags.IntVar(&localRunStartOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&localRunStartOpts.start, "start", "", "starting run id (excluded) to fetch")
	flags.BoolVar(&localRunStartOpts.untracked, "untracked", true, "push untracked files")
	flags.BoolVar(&localRunStartOpts.ignored, "ignored", false, "push ignored files")

	cmdLocalRun.AddCommand(cmdLocalRunStart)
}

func localRunStart(cmd *cobra.Command, args []string) error {
	gs := gitsave.NewGitSave(logger, &gitsave.GitSaveConfig{
		AddUntracked: localRunStartOpts.untracked,
		AddIgnored:   localRunStartOpts.ignored,
	})

	branch := "gitsavebranch-" + uuid.NewV4().String()

	if err := gs.Save("agola local run", branch); err != nil {
		log.Fatalf("err: %v", err)
	}

	log.Infof("pushing branch")
	if err := gitsave.GitPush("", "http://172.17.0.1:8000/repos/sgotti/test02.git", "refs/gitsave/"+branch); err != nil {
		return err
	}

	return nil
}
