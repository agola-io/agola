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
