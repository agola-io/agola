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
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdUserLACreate = &cobra.Command{
	Use:   "create",
	Short: "create a user linkedaccount",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userLACreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userLACreateOptions struct {
	username                  string
	remoteSourceName          string
	remoteSourceLoginName     string
	remoteSourceLoginPassword string
}

var userLACreateOpts userLACreateOptions

func init() {
	flags := cmdUserLACreate.Flags()

	flags.StringVarP(&userLACreateOpts.username, "username", "n", "", "user name")
	flags.StringVarP(&userLACreateOpts.remoteSourceName, "remote-source", "r", "", "remote source name")
	flags.StringVar(&userLACreateOpts.remoteSourceLoginName, "remote-name", "", "remote source login name")
	flags.StringVar(&userLACreateOpts.remoteSourceLoginPassword, "remote-password", "", "remote source password")

	cmdUserLACreate.MarkFlagRequired("username")
	cmdUserLACreate.MarkFlagRequired("remote-source")

	cmdUserLA.AddCommand(cmdUserLACreate)
}

func userLACreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateUserLARequest{
		RemoteSourceName:          userLACreateOpts.remoteSourceName,
		RemoteSourceLoginName:     userLACreateOpts.remoteSourceLoginName,
		RemoteSourceLoginPassword: userLACreateOpts.remoteSourceLoginPassword,
	}

	log.Infof("creating linked account for user %q", userLACreateOpts.username)
	resp, _, err := gwclient.CreateUserLA(context.TODO(), userLACreateOpts.username, req)
	if err != nil {
		return errors.Wrapf(err, "failed to create linked account")
	}
	if resp.Oauth2Redirect != "" {
		log.Infof("visit %s", resp.Oauth2Redirect)

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter code: ")
		code, _ := reader.ReadString('\n')
		code = strings.TrimSpace(code)
		log.Infof("code: %s", code)

		req := &api.CreateUserLARequest{
			RemoteSourceName: userLACreateOpts.remoteSourceName,
		}
		resp, _, err = gwclient.CreateUserLA(context.TODO(), userLACreateOpts.username, req)
		if err != nil {
			return errors.Wrapf(err, "failed to create linked account")
		}
	}

	log.Infof("linked account for user %q created, ID: %s", userLACreateOpts.username, resp.LinkedAccount.ID)

	return nil
}
