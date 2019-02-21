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
	name               string
	rsType             string
	authType           string
	apiURL             string
	oauth2ClientID     string
	oauth2ClientSecret string
}

var remoteSourceCreateOpts remoteSourceCreateOptions

func init() {
	flags := cmdRemoteSourceCreate.Flags()

	flags.StringVarP(&remoteSourceCreateOpts.name, "name", "n", "", "remotesource name")
	flags.StringVar(&remoteSourceCreateOpts.rsType, "type", "", "remotesource type")
	flags.StringVar(&remoteSourceCreateOpts.authType, "auth-type", "", "remote source auth type")
	flags.StringVar(&remoteSourceCreateOpts.apiURL, "api-url", "", "remotesource api url")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientID, "clientid", "", "remotesource oauth2 client id")
	flags.StringVar(&remoteSourceCreateOpts.oauth2ClientSecret, "secret", "", "remotesource oauth2 secret")

	cmdRemoteSourceCreate.MarkFlagRequired("name")
	cmdRemoteSourceCreate.MarkFlagRequired("type")
	cmdRemoteSourceCreate.MarkFlagRequired("auth-type")
	cmdRemoteSourceCreate.MarkFlagRequired("api-url")

	cmdRemoteSource.AddCommand(cmdRemoteSourceCreate)
}

func remoteSourceCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateRemoteSourceRequest{
		Name:               remoteSourceCreateOpts.name,
		Type:               remoteSourceCreateOpts.rsType,
		AuthType:           remoteSourceCreateOpts.authType,
		APIURL:             remoteSourceCreateOpts.apiURL,
		Oauth2ClientID:     remoteSourceCreateOpts.oauth2ClientID,
		Oauth2ClientSecret: remoteSourceCreateOpts.oauth2ClientSecret,
	}

	log.Infof("creating remotesource")
	remoteSource, _, err := gwclient.CreateRemoteSource(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create remotesource")
	}
	log.Infof("remotesource %s created, ID: %s", remoteSource.Name, remoteSource.ID)

	return nil
}
