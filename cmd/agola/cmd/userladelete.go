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

	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdUserLADelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a user linkedaccount",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userLADelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userLADeleteOptions struct {
	userName string
	laID     string
}

var userLADeleteOpts userLADeleteOptions

func init() {
	flags := cmdUserLADelete.Flags()

	flags.StringVarP(&userLADeleteOpts.userName, "username", "n", "", "user name")
	flags.StringVar(&userLADeleteOpts.laID, "laid", "", "linked account id")

	if err := cmdUserLADelete.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}
	if err := cmdUserLADelete.MarkFlagRequired("laid"); err != nil {
		log.Fatal(err)
	}

	cmdUserLA.AddCommand(cmdUserLADelete)
}

func userLADelete(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	userName := userLADeleteOpts.userName
	laID := userLADeleteOpts.laID

	log.Infof("deleting linked account %q for user %q", laID, userName)
	_, err := gwclient.DeleteUserLA(context.TODO(), userName, laID)
	if err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}

	log.Infof("linked account %q for user %q deleted", laID, userName)

	return nil
}
