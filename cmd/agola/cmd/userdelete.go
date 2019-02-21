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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdUserDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a user",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userDeleteOptions struct {
	username string
}

var userDeleteOpts userDeleteOptions

func init() {
	flags := cmdUserDelete.Flags()

	flags.StringVarP(&userDeleteOpts.username, "username", "n", "", "user name")

	cmdUserDelete.MarkFlagRequired("username")

	cmdUser.AddCommand(cmdUserDelete)
}

func userDelete(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("deleting user %q", userDeleteOpts.username)
	if _, err := gwclient.DeleteUser(context.TODO(), userDeleteOpts.username); err != nil {
		return errors.Wrapf(err, "failed to delete user")
	}

	return nil
}
