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
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdOrgMemberList = &cobra.Command{
	Use:   "list",
	Short: "lists organization members",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgMemberListOptions struct {
	orgname  string
	username string
	role     string
}

var orgMemberListOpts orgMemberListOptions

func init() {
	flags := cmdOrgMemberList.Flags()

	flags.StringVarP(&orgMemberListOpts.orgname, "orgname", "n", "", "organization name")

	cmdOrgMemberList.MarkFlagRequired("orgname")

	cmdOrgMember.AddCommand(cmdOrgMemberList)
}

func orgMemberList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	orgMembers, _, err := gwclient.GetOrgMembers(context.TODO(), orgMemberListOpts.orgname)
	if err != nil {
		return errors.Wrapf(err, "failed to get organization member")
	}

	out, err := json.MarshalIndent(orgMembers, "", "\t")
	if err != nil {
		return err
	}
	os.Stdout.Write(out)

	return nil
}
