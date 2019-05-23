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

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdRemoteSourceUpdate = &cobra.Command{
	Use:   "update",
	Short: "update a remotesource",
	Run: func(cmd *cobra.Command, args []string) {
		if err := remoteSourceUpdate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type remoteSourceUpdateOptions struct {
	ref string

	newName             string
	apiURL              string
	skipVerify          bool
	oauth2ClientID      string
	oauth2ClientSecret  string
	sshHostKey          string
	skipSSHHostKeyCheck bool
}

var remoteSourceUpdateOpts remoteSourceUpdateOptions

func init() {
	flags := cmdRemoteSourceUpdate.Flags()

	flags.StringVarP(&remoteSourceUpdateOpts.ref, "ref", "", "", "current remotesource name or id")
	flags.StringVarP(&remoteSourceUpdateOpts.newName, "new-name", "", "", "remotesource new name")
	flags.StringVar(&remoteSourceUpdateOpts.apiURL, "api-url", "", "remotesource api url")
	flags.BoolVarP(&remoteSourceUpdateOpts.skipVerify, "skip-verify", "", false, "skip remote source api tls certificate verification")
	flags.StringVar(&remoteSourceUpdateOpts.oauth2ClientID, "clientid", "", "remotesource oauth2 client id")
	flags.StringVar(&remoteSourceUpdateOpts.oauth2ClientSecret, "secret", "", "remotesource oauth2 secret")
	flags.StringVar(&remoteSourceUpdateOpts.sshHostKey, "ssh-host-key", "", "remotesource ssh public host key")
	flags.BoolVarP(&remoteSourceUpdateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")

	cmdRemoteSourceUpdate.MarkFlagRequired("ref")

	cmdRemoteSource.AddCommand(cmdRemoteSourceUpdate)
}

func remoteSourceUpdate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.UpdateRemoteSourceRequest{}

	flags := cmd.Flags()
	if flags.Changed("new-name") {
		req.Name = &remoteSourceUpdateOpts.newName
	}
	if flags.Changed("api-url") {
		req.APIURL = &remoteSourceUpdateOpts.apiURL
	}
	if flags.Changed("skip-verify") {
		req.SkipVerify = &remoteSourceUpdateOpts.skipVerify
	}
	if flags.Changed("clientid") {
		req.Oauth2ClientID = &remoteSourceUpdateOpts.oauth2ClientID
	}
	if flags.Changed("secret") {
		req.Oauth2ClientSecret = &remoteSourceUpdateOpts.oauth2ClientSecret
	}
	if flags.Changed("ssh-host-key") {
		req.SSHHostKey = &remoteSourceUpdateOpts.sshHostKey
	}
	if flags.Changed("skip-ssh-host-key-check") {
		req.SkipSSHHostKeyCheck = &remoteSourceUpdateOpts.skipSSHHostKeyCheck
	}

	log.Infof("updating remotesource")
	remoteSource, _, err := gwclient.UpdateRemoteSource(context.TODO(), remoteSourceUpdateOpts.ref, req)
	if err != nil {
		return errors.Errorf("failed to update remotesource: %w", err)
	}
	log.Infof("remotesource %s updated, ID: %s", remoteSource.Name, remoteSource.ID)

	return nil
}
