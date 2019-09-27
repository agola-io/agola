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

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectSecretUpdate = &cobra.Command{
	Use:   "update",
	Short: "update a project local secret",
	Long: `update a project local secret

The secret data should be provided by a yaml document. Examples:

data01: secretvalue01
data02: secretvalue02
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretUpdate(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type secretUpdateOptions struct {
	parentRef string
	name      string
	newName   string
	file      string
}

var secretUpdateOpts secretUpdateOptions

func init() {
	flags := cmdProjectSecretUpdate.Flags()

	flags.StringVar(&secretUpdateOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&secretUpdateOpts.name, "name", "n", "", "secret name")
	flags.StringVarP(&secretUpdateOpts.newName, "new-name", "", "", "secret new name")
	flags.StringVarP(&secretUpdateOpts.file, "file", "f", "", `yaml file containing the secret data (use "-" to read from stdin)`)

	if err := cmdProjectSecretUpdate.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectSecretUpdate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectSecretUpdate.MarkFlagRequired("file"); err != nil {
		log.Fatal(err)
	}

	cmdProjectSecret.AddCommand(cmdProjectSecretUpdate)
}

func secretUpdate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// "github.com/ghodss/yaml" doesn't provide a streaming decoder
	var data []byte
	var err error
	if secretUpdateOpts.file == "-" {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		data, err = ioutil.ReadFile(secretUpdateOpts.file)
		if err != nil {
			return err
		}
	}

	var secretData map[string]string
	if err := yaml.Unmarshal(data, &secretData); err != nil {
		log.Fatalf("failed to unmarshal secret: %v", err)
	}
	req := &gwapitypes.UpdateSecretRequest{
		Name: secretUpdateOpts.name,
		Type: gwapitypes.SecretTypeInternal,
		Data: secretData,
	}

	flags := cmd.Flags()
	if flags.Changed("new-name") {
		req.Name = secretUpdateOpts.newName
	}

	switch ownertype {
	case "project":
		log.Infof("creating project secret")
		secret, _, err := gwclient.UpdateProjectSecret(context.TODO(), secretUpdateOpts.parentRef, secretUpdateOpts.name, req)
		if err != nil {
			return errors.Errorf("failed to update project secret: %w", err)
		}
		log.Infof("project secret %q updated, ID: %q", secret.Name, secret.ID)
	case "projectgroup":
		log.Infof("creating project group secret")
		secret, _, err := gwclient.UpdateProjectGroupSecret(context.TODO(), secretUpdateOpts.parentRef, secretUpdateOpts.name, req)
		if err != nil {
			return errors.Errorf("failed to update project group secret: %w", err)
		}
		log.Infof("project group secret %q updated, ID: %q", secret.Name, secret.ID)
	}

	return nil
}
