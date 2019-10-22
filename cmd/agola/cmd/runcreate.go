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

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
)

var cmdRunCreate = &cobra.Command{
	Use: "create",
	Run: func(cmd *cobra.Command, args []string) {
		if err := runCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "create",
}

type runCreateOptions struct {
	projectRef string
	branch     string
	tag        string
	ref        string
	commitSHA  string
}

var runCreateOpts runCreateOptions

func init() {
	flags := cmdRunCreate.Flags()

	flags.StringVar(&runCreateOpts.projectRef, "project", "", "project id or full path")
	flags.StringVar(&runCreateOpts.branch, "branch", "", "git branch")
	flags.StringVar(&runCreateOpts.tag, "tag", "", "git tag")
	flags.StringVar(&runCreateOpts.ref, "ref", "", "git ref")
	flags.StringVar(&runCreateOpts.commitSHA, "commit-sha", "", "git commit sha")

	if err := cmdRunCreate.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}

	cmdRun.AddCommand(cmdRunCreate)
}

func runCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	set := 0
	flags := cmd.Flags()
	if flags.Changed("branch") {
		set++
	}
	if flags.Changed("tag") {
		set++
	}
	if flags.Changed("ref") {
		set++
	}
	if set != 1 {
		return fmt.Errorf(`one of "--branch", "--tag" or "--ref" must be provided`)
	}

	req := &gwapitypes.ProjectCreateRunRequest{
		Branch:    runCreateOpts.branch,
		Tag:       runCreateOpts.tag,
		Ref:       runCreateOpts.ref,
		CommitSHA: runCreateOpts.commitSHA,
	}

	_, err := gwclient.ProjectCreateRun(context.TODO(), runCreateOpts.projectRef, req)

	return err
}
