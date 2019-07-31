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

var cmdUserCreate = &cobra.Command{
	Use:   "create",
	Short: "create a user",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userCreateOptions struct {
	username string
}

var userCreateOpts userCreateOptions

func init() {
	flags := cmdUserCreate.Flags()

	flags.StringVarP(&userCreateOpts.username, "username", "n", "", "user name")

	if err := cmdUserCreate.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}

	cmdUser.AddCommand(cmdUserCreate)
}

func userCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.CreateUserRequest{
		UserName: userCreateOpts.username,
	}

	log.Infof("creating user")
	user, _, err := gwclient.CreateUser(context.TODO(), req)
	if err != nil {
		return errors.Errorf("failed to create user: %w", err)
	}
	log.Infof("user %q created, ID: %q", user.UserName, user.ID)

	return nil
}
