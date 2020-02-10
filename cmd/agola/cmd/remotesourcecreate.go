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

	"agola.io/agola/internal/gitsources/github"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	"agola.io/agola/util"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
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
	registrationEnabled bool
	loginEnabled        bool
}

var remoteSourceCreateOpts remoteSourceCreateOptions

func init() {
	flags := cmdRemoteSourceCreate.Flags()

	flags.StringVarP(&remoteSourceCreateOpts.name, "name", "n", "", "remotesource name")
	flags.StringVar(&remoteSourceCreateOpts.rsType, "type", "", "remotesource type")
	flags.StringVar(&remoteSourceCreateOpts.authType, "auth-type", "", "remote source auth type")
	flags.StringVar(&remoteSourceCreateOpts.apiURL, "api-url", "", `remotesource api url (when type is "github" defaults to "https://api.github.com")`)
	flags.BoolVarP(&remoteSourceCreateOpts.skipVerify, "skip-verify", "", false, "skip remote source api tls certificate verification")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientID, "clientid", "", "remotesource oauth2 client id")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientSecret, "secret", "", "remotesource oauth2 secret")
	flags.StringVar(&remoteSourceCreateOpts.sshHostKey, "ssh-host-key", "", "remotesource ssh public host key")
	flags.BoolVarP(&remoteSourceCreateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")
	flags.BoolVar(&remoteSourceCreateOpts.registrationEnabled, "registration-enabled", true, "enabled/disable user registration with this remote source")
	flags.BoolVar(&remoteSourceCreateOpts.loginEnabled, "login-enabled", true, "enabled/disable user login with this remote source")

	if err := cmdRemoteSourceCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdRemoteSourceCreate.MarkFlagRequired("type"); err != nil {
		log.Fatal(err)
	}
	if err := cmdRemoteSourceCreate.MarkFlagRequired("auth-type"); err != nil {
		log.Fatal(err)
	}

	cmdRemoteSource.AddCommand(cmdRemoteSourceCreate)
}

func remoteSourceCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	flags := cmd.Flags()

	// for github remote source type, set defaults for github.com
	if remoteSourceCreateOpts.rsType == "github" {
		if !flags.Changed("api-url") {
			remoteSourceCreateOpts.apiURL = github.GitHubAPIURL
		}
		if remoteSourceCreateOpts.apiURL == github.GitHubAPIURL && !flags.Changed("ssh-host-key") {
			remoteSourceCreateOpts.sshHostKey = github.GitHubSSHHostKey
		}
	}

	if remoteSourceCreateOpts.apiURL == "" {
		return errors.Errorf(`required flag "api-url" not set`)
	}

	req := &gwapitypes.CreateRemoteSourceRequest{
		Name:                remoteSourceCreateOpts.name,
		Type:                remoteSourceCreateOpts.rsType,
		AuthType:            remoteSourceCreateOpts.authType,
		APIURL:              remoteSourceCreateOpts.apiURL,
		SkipVerify:          remoteSourceCreateOpts.skipVerify,
		Oauth2ClientID:      remoteSourceCreateOpts.oauth2ClientID,
		Oauth2ClientSecret:  remoteSourceCreateOpts.oauth2ClientSecret,
		SSHHostKey:          remoteSourceCreateOpts.sshHostKey,
		SkipSSHHostKeyCheck: remoteSourceCreateOpts.skipSSHHostKeyCheck,
		RegistrationEnabled: util.BoolP(remoteSourceCreateOpts.registrationEnabled),
		LoginEnabled:        util.BoolP(remoteSourceCreateOpts.loginEnabled),
	}

	log.Infof("creating remotesource")
	remoteSource, _, err := gwclient.CreateRemoteSource(context.TODO(), req)
	if err != nil {
		return errors.Errorf("failed to create remotesource: %w", err)
	}
	log.Infof("remotesource %s created, ID: %s", remoteSource.Name, remoteSource.ID)

	return nil
}
