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
	"os"

	"agola.io/agola/internal/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/ghodss/yaml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdProjectSecretCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project secret",
	Long: `create a project secret

The secret data should be provided by a yaml document. Examples:

data01: secretvalue01
data02: secretvalue02
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretCreate(cmd, "project", args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type secretCreateOptions struct {
	parentRef string
	name      string
	file      string
}

var secretCreateOpts secretCreateOptions

func init() {
	flags := cmdProjectSecretCreate.Flags()

	flags.StringVar(&secretCreateOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&secretCreateOpts.name, "name", "n", "", "secret name")
	flags.StringVarP(&secretCreateOpts.file, "file", "f", "", `yaml file containing the secret data (use "-" to read from stdin)`)

	if err := cmdProjectSecretCreate.MarkFlagRequired("project"); err != nil {
		log.Fatal().Err(err).Send()
	}
	if err := cmdProjectSecretCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal().Err(err).Send()
	}
	if err := cmdProjectSecretCreate.MarkFlagRequired("file"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdProjectSecret.AddCommand(cmdProjectSecretCreate)
}

func secretCreate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// "github.com/ghodss/yaml" doesn't provide a streaming decoder
	var data []byte
	var err error
	if secretCreateOpts.file == "-" {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		data, err = ioutil.ReadFile(secretCreateOpts.file)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	var secretData map[string]string
	if err := yaml.Unmarshal(data, &secretData); err != nil {
		log.Fatal().Msgf("failed to unmarshal secret: %v", err)
	}
	req := &gwapitypes.CreateSecretRequest{
		Name: secretCreateOpts.name,
		Type: gwapitypes.SecretTypeInternal,
		Data: secretData,
	}

	switch ownertype {
	case "project":
		log.Info().Msgf("creating project secret")
		secret, _, err := gwclient.CreateProjectSecret(context.TODO(), secretCreateOpts.parentRef, req)
		if err != nil {
			return errors.Wrapf(err, "failed to create project secret")
		}
		log.Info().Msgf("project secret %q created, ID: %q", secret.Name, secret.ID)
	case "projectgroup":
		log.Info().Msgf("creating project group secret")
		secret, _, err := gwclient.CreateProjectGroupSecret(context.TODO(), secretCreateOpts.parentRef, req)
		if err != nil {
			return errors.Wrapf(err, "failed to create project group secret")
		}
		log.Info().Msgf("project group secret %q created, ID: %q", secret.Name, secret.ID)
	}

	return nil
}
