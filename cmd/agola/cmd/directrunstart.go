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

	gitsave "github.com/sorintlab/agola/internal/git-save"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/util"

	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
)

var cmdDirectRunStart = &cobra.Command{
	Use: "start",
	Run: func(cmd *cobra.Command, args []string) {
		if err := directRunStart(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "executes a run from a local git repository",
}

type directRunStartOptions struct {
	statusFilter []string
	labelFilter  []string
	limit        int
	start        string
	untracked    bool
	ignored      bool
}

var directRunStartOpts directRunStartOptions

func init() {
	flags := cmdDirectRunStart.PersistentFlags()

	flags.StringSliceVarP(&directRunStartOpts.statusFilter, "status", "s", nil, "filter runs matching the provided status. This option can be repeated multiple times")
	flags.StringArrayVarP(&directRunStartOpts.labelFilter, "label", "l", nil, "filter runs matching the provided label. This option can be repeated multiple times, in this case only runs matching all the labels will be returned")
	flags.IntVar(&directRunStartOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&directRunStartOpts.start, "start", "", "starting run id (excluded) to fetch")
	flags.BoolVar(&directRunStartOpts.untracked, "untracked", true, "push untracked files")
	flags.BoolVar(&directRunStartOpts.ignored, "ignored", false, "push ignored files")

	cmdDirectRun.AddCommand(cmdDirectRunStart)
}

func directRunStart(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	user, _, err := gwclient.GetCurrentUser(context.TODO())
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	// setup unique local git repo uuid
	git := &util.Git{}
	repoUUID, _ := git.ConfigGet(context.Background(), "agola.repouuid")
	if repoUUID == "" {
		repoUUID = uuid.NewV4().String()
		if _, err := git.ConfigSet(context.Background(), "agola.repouuid", repoUUID); err != nil {
			log.Fatalf("failed to set agola repo uid in git config: %v", err)
		}
	}

	gs := gitsave.NewGitSave(logger, &gitsave.GitSaveConfig{
		AddUntracked: directRunStartOpts.untracked,
		AddIgnored:   directRunStartOpts.ignored,
	})

	branch := "gitsavebranch-" + uuid.NewV4().String()

	if _, err := gs.Save("agola direct run", branch); err != nil {
		log.Fatalf("err: %v", err)
	}

	log.Infof("pushing branch")
	repoURL := fmt.Sprintf("%s/repos/%s/%s.git", gatewayURL, user.ID, repoUUID)
	if err := gitsave.GitPush("", repoURL, "refs/gitsave/"+branch); err != nil {
		return err
	}

	return nil
}
