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

var cmdOrgMemberAdd = &cobra.Command{
	Use:   "add",
	Short: "adds or updates an organization member",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberAdd(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgMemberAddOptions struct {
	orgname  string
	username string
	role     string
}

var orgMemberAddOpts orgMemberAddOptions

func init() {
	flags := cmdOrgMemberAdd.Flags()

	flags.StringVarP(&orgMemberAddOpts.orgname, "orgname", "n", "", "organization name")
	flags.StringVar(&orgMemberAddOpts.username, "username", "", "user name")
	flags.StringVarP(&orgMemberAddOpts.role, "role", "r", "member", "member role (owner or member)")

	if err := cmdOrgMemberAdd.MarkFlagRequired("orgname"); err != nil {
		log.Fatal(err)
	}
	if err := cmdOrgMemberAdd.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}

	cmdOrgMember.AddCommand(cmdOrgMemberAdd)
}

func orgMemberAdd(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	log.Infof("adding/updating member %q to organization %q with role %q", orgMemberAddOpts.username, orgMemberAddOpts.orgname, orgMemberAddOpts.role)
	_, _, err := gwclient.AddOrgMember(context.TODO(), orgMemberAddOpts.orgname, orgMemberAddOpts.username, gwapitypes.MemberRole(orgMemberAddOpts.role))
	if err != nil {
		return errors.Errorf("failed to add/update organization member: %w", err)
	}

	return nil
}
