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

	"agola.io/agola/internal/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdUserCreate = &cobra.Command{
	Use:   "create",
	Short: "create a user",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userCreate(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
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
		log.Fatal().Err(err).Send()
	}

	cmdUser.AddCommand(cmdUserCreate)
}

func userCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.CreateUserRequest{
		UserName: userCreateOpts.username,
	}

	log.Info().Msgf("creating user")
	user, _, err := gwclient.CreateUser(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create user")
	}
	log.Info().Msgf("user %q created, ID: %q", user.UserName, user.ID)

	return nil
}
