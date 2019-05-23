// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"

	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
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
		return errors.Errorf("failed to create linked account: %w", err)
	}
	if resp.Oauth2Redirect != "" {
		log.Infof("visit %s to continue", resp.Oauth2Redirect)
	} else {
		log.Infof("linked account for user %q created, ID: %s", userLACreateOpts.username, resp.LinkedAccount.ID)
	}

	return nil
}
