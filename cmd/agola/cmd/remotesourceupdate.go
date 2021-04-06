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
	"io/ioutil"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
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
	tlsClientKeyFile    string
	tlsClientCertFile   string
	skipVerify          bool
	oauth2ClientID      string
	oauth2ClientSecret  string
	sshHostKey          string
	skipSSHHostKeyCheck bool
	registrationEnabled bool
	loginEnabled        bool
}

var remoteSourceUpdateOpts remoteSourceUpdateOptions

func init() {
	flags := cmdRemoteSourceUpdate.Flags()

	flags.StringVarP(&remoteSourceUpdateOpts.ref, "ref", "", "", "current remotesource name or id")
	flags.StringVarP(&remoteSourceUpdateOpts.newName, "new-name", "", "", "remotesource new name")
	flags.StringVar(&remoteSourceUpdateOpts.apiURL, "api-url", "", "remotesource api url")
	flags.StringVar(&remoteSourceUpdateOpts.tlsClientKeyFile, "tls-client-key", "", "remotesource tls client key")
	flags.StringVar(&remoteSourceUpdateOpts.tlsClientCertFile, "tls-client-cert", "", "remotesource tls client certificate")
	flags.BoolVarP(&remoteSourceUpdateOpts.skipVerify, "skip-verify", "", false, "skip remote source api tls certificate verification")
	flags.StringVar(&remoteSourceUpdateOpts.oauth2ClientID, "clientid", "", "remotesource oauth2 client id")
	flags.StringVar(&remoteSourceUpdateOpts.oauth2ClientSecret, "secret", "", "remotesource oauth2 secret")
	flags.StringVar(&remoteSourceUpdateOpts.sshHostKey, "ssh-host-key", "", "remotesource ssh public host key")
	flags.BoolVarP(&remoteSourceUpdateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")
	flags.BoolVar(&remoteSourceUpdateOpts.registrationEnabled, "registration-enabled", false, "enabled/disable user registration with this remote source")
	flags.BoolVar(&remoteSourceUpdateOpts.loginEnabled, "login-enabled", false, "enabled/disable user login with this remote source")

	if err := cmdRemoteSourceUpdate.MarkFlagRequired("ref"); err != nil {
		log.Fatal(err)
	}

	cmdRemoteSource.AddCommand(cmdRemoteSourceUpdate)
}

func remoteSourceUpdate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.UpdateRemoteSourceRequest{}

	flags := cmd.Flags()
	if flags.Changed("new-name") {
		req.Name = &remoteSourceUpdateOpts.newName
	}
	if flags.Changed("api-url") {
		req.APIURL = &remoteSourceUpdateOpts.apiURL
	}
	if flags.Changed("tls-client-key") && flags.Changed("tls-client-cert") {
		keyData, err := ioutil.ReadFile(remoteSourceUpdateOpts.tlsClientKeyFile)
		if err != nil {
			return err
		}
		certData, err := ioutil.ReadFile(remoteSourceUpdateOpts.tlsClientCertFile)
		if err != nil {
			return err
		}
		keyText := string(keyData)
		certText := string(certData)
		req.TlsClientKey = &keyText
		req.TlsClientCert = &certText
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
	if flags.Changed("registration-enabled") {
		req.RegistrationEnabled = &remoteSourceUpdateOpts.registrationEnabled
	}
	if flags.Changed("login-enabled") {
		req.LoginEnabled = &remoteSourceUpdateOpts.loginEnabled
	}

	log.Infof("updating remotesource")
	remoteSource, _, err := gwclient.UpdateRemoteSource(context.TODO(), remoteSourceUpdateOpts.ref, req)
	if err != nil {
		return errors.Errorf("failed to update remotesource: %w", err)
	}
	log.Infof("remotesource %s updated, ID: %s", remoteSource.Name, remoteSource.ID)

	return nil
}
