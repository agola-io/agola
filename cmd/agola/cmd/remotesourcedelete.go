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
	"fmt"
	"strings"
)

var cmdRemoteSourceDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a remotesource",
	Run: func(cmd *cobra.Command, args []string) {
		if err := remoteSourceDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type remoteSourceDeleteOptions struct {
	name	string
	yes	bool
}

var remoteSourceDeleteOpts remoteSourceDeleteOptions

func init() {
	flags := cmdRemoteSourceDelete.Flags()

	flags.StringVarP(&remoteSourceDeleteOpts.name, "name", "n", "", "remotesource name")
	flags.BoolVarP(&remoteSourceDeleteOpts.yes, "yes", "y", false, "delete remote source without ask confirmation")


	if err := cmdRemoteSourceDelete.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}

	cmdRemoteSource.AddCommand(cmdRemoteSourceDelete)
}

func remoteSourceDelete(cmd *cobra.Command, args []string) error {

	var response string
	message := `
##################################
#                                #
#      W  A  R  N  I  N  G       #
#                                #
##################################

Deleting a remote source will invalidate all the user linked accounts and consequently all the projects connected with that linked account!
The users won't be able to login anymore via oauth with the remote source and agola won't be able to update commit statuses or reconfigure the project deploy key and webhooks making the project unusable (visit https://agola.io/doc for more information).

Are you sure you want to delete %s (yes to confirm)? `

	gwclient := gwclient.NewClient(gatewayURL, token)

	if !remoteSourceDeleteOpts.yes {
		fmt.Printf(message, remoteSourceDeleteOpts.name)

		_, err := fmt.Scanln(&response)
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response != "yes" {
			return nil
		}
	}

	log.Infof("deleting remotesource")
	_, err := gwclient.DeleteRemoteSource(context.TODO(), remoteSourceDeleteOpts.name)
	if err != nil {
		return errors.Errorf("failed to delete remotesource: %w", err)
	}
	log.Infof("remotesource %s deleted", remoteSourceDeleteOpts.name)

	return nil
}
