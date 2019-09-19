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
	"encoding/json"
	"fmt"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectSecretList = &cobra.Command{
	Use:   "list",
	Short: "list project secrets",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretList(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type secretListOptions struct {
	parentRef string
}

var secretListOpts secretListOptions

func init() {
	flags := cmdProjectSecretList.Flags()

	flags.StringVar(&secretListOpts.parentRef, "project", "", "project id or full path")

	if err := cmdProjectSecretList.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}

	cmdProjectSecret.AddCommand(cmdProjectSecretList)
}

func secretList(cmd *cobra.Command, ownertype string, args []string) error {
	if err := printSecrets(ownertype, fmt.Sprintf("%s secrets", ownertype), false, false); err != nil {
		return err
	}
	if err := printSecrets(ownertype, "All secrets (local and inherited)", true, true); err != nil {
		return err
	}
	return nil
}

func printSecrets(ownertype, description string, tree, removeoverridden bool) error {

	var err error
	var secrets []*gwapitypes.SecretResponse

	gwclient := gwclient.NewClient(gatewayURL, token)

	switch ownertype {
	case "project":
		secrets, _, err = gwclient.GetProjectSecrets(context.TODO(), secretListOpts.parentRef, tree, removeoverridden)
	case "projectgroup":
		secrets, _, err = gwclient.GetProjectGroupSecrets(context.TODO(), secretListOpts.parentRef, tree, removeoverridden)
	}
	if err != nil {
		return errors.Errorf("failed to list %s secrets: %w", ownertype, err)
	}
	prettyJSON, err := json.MarshalIndent(secrets, "", "\t")
	if err != nil {
		return errors.Errorf("failed to convert %s secrets to json: %w", ownertype, err)
	}
	fmt.Printf("%s:\n%s\n", description, string(prettyJSON))
	return nil
}
