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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/gitsources/github"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/spf13/cobra"
)

var cmdRemoteSourceCreate = &cobra.Command{
	Use:   "create",
	Short: "create a remotesource",
	Run: func(cmd *cobra.Command, args []string) {
		if err := remoteSourceCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type remoteSourceCreateOptions struct {
	name                string
	rsType              string
	authType            string
	apiURL              string
	skipVerify          bool
	oauth2ClientID      string
	oauth2ClientSecret  string
	sshHostKey          string
	skipSSHHostKeyCheck bool
}

var remoteSourceCreateOpts remoteSourceCreateOptions

func init() {
	flags := cmdRemoteSourceCreate.Flags()

	flags.StringVarP(&remoteSourceCreateOpts.name, "name", "n", "", "remotesource name")
	flags.StringVar(&remoteSourceCreateOpts.rsType, "type", "", "remotesource type")
	flags.StringVar(&remoteSourceCreateOpts.authType, "auth-type", "", "remote source auth type")
	flags.StringVar(&remoteSourceCreateOpts.apiURL, "api-url", "", "remotesource api url")
	flags.BoolVarP(&remoteSourceCreateOpts.skipVerify, "skip-verify", "", false, "skip remote source api tls certificate verification")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientID, "clientid", "", "remotesource oauth2 client id")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientSecret, "secret", "", "remotesource oauth2 secret")
	flags.StringVar(&remoteSourceCreateOpts.sshHostKey, "ssh-host-key", "", "remotesource ssh public host key")
	flags.BoolVarP(&remoteSourceCreateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")

	cmdRemoteSourceCreate.MarkFlagRequired("name")
	cmdRemoteSourceCreate.MarkFlagRequired("type")
	cmdRemoteSourceCreate.MarkFlagRequired("auth-type")
	cmdRemoteSourceCreate.MarkFlagRequired("api-url")

	cmdRemoteSource.AddCommand(cmdRemoteSourceCreate)
}

func remoteSourceCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	// for github remote source type, set defaults to github.com if no apiurl provided
	if remoteSourceCreateOpts.rsType == string(types.RemoteSourceTypeGithub) {
		remoteSourceCreateOpts.apiURL = github.GitHubAPIURL
	}

	req := &api.CreateRemoteSourceRequest{
		Name:                remoteSourceCreateOpts.name,
		Type:                remoteSourceCreateOpts.rsType,
		AuthType:            remoteSourceCreateOpts.authType,
		APIURL:              remoteSourceCreateOpts.apiURL,
		SkipVerify:          remoteSourceCreateOpts.skipVerify,
		Oauth2ClientID:      remoteSourceCreateOpts.oauth2ClientID,
		Oauth2ClientSecret:  remoteSourceCreateOpts.oauth2ClientSecret,
		SSHHostKey:          remoteSourceCreateOpts.sshHostKey,
		SkipSSHHostKeyCheck: remoteSourceCreateOpts.skipSSHHostKeyCheck,
	}

	log.Infof("creating remotesource")
	remoteSource, _, err := gwclient.CreateRemoteSource(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create remotesource")
	}
	log.Infof("remotesource %s created, ID: %s", remoteSource.Name, remoteSource.ID)

	return nil
}
