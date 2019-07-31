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
	"path"

	gitsave "agola.io/agola/internal/git-save"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

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
	flags := cmdDirectRunStart.Flags()

	flags.StringSliceVarP(&directRunStartOpts.statusFilter, "status", "s", nil, "filter runs matching the provided status. This option can be repeated multiple times")
	flags.StringArrayVarP(&directRunStartOpts.labelFilter, "label", "l", nil, "filter runs matching the provided label. This option can be repeated multiple times, in this case only runs matching all the labels will be returned")
	flags.IntVar(&directRunStartOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&directRunStartOpts.start, "start", "", "starting run id (excluded) to fetch")
	flags.BoolVar(&directRunStartOpts.untracked, "untracked", true, "push untracked files")
	flags.BoolVar(&directRunStartOpts.ignored, "ignored", false, "push ignored files")

	cmdDirectRun.AddCommand(cmdDirectRunStart)
}

func directRunStart(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	user, _, err := gwclient.GetCurrentUser(context.TODO())
	if err != nil {
		return err
	}

	// setup unique local git repo uuid
	git := &util.Git{}
	repoUUID, _ := git.ConfigGet(context.Background(), "agola.repouuid")
	if repoUUID == "" {
		repoUUID = uuid.NewV4().String()
		if _, err := git.ConfigSet(context.Background(), "agola.repouuid", repoUUID); err != nil {
			return fmt.Errorf("failed to set agola repo uid in git config: %v", err)
		}
	}

	gs := gitsave.NewGitSave(logger, &gitsave.GitSaveConfig{
		AddUntracked: directRunStartOpts.untracked,
		AddIgnored:   directRunStartOpts.ignored,
	})

	branch := "gitsavebranch-" + uuid.NewV4().String()
	message := "agola direct run"

	commitSHA, err := gs.Save(message, branch)
	if err != nil {
		return err
	}

	log.Infof("pushing branch")
	repoPath := fmt.Sprintf("%s/%s", user.ID, repoUUID)
	repoURL := fmt.Sprintf("%s/repos/%s/%s.git", gatewayURL, user.ID, repoUUID)

	// push to a branch with default branch refs "refs/heads/branch"
	if err := gitsave.GitPush("", repoURL, fmt.Sprintf("%s:refs/heads/%s", path.Join(gs.RefsPrefix(), branch), branch)); err != nil {
		return err
	}

	log.Infof("starting direct run")
	req := &gwapitypes.UserCreateRunRequest{
		RepoUUID:  repoUUID,
		RepoPath:  repoPath,
		Branch:    branch,
		CommitSHA: commitSHA,
		Message:   message,
	}
	if _, err := gwclient.UserCreateRun(context.TODO(), req); err != nil {
		return err
	}

	return nil
}
