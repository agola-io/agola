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

var cmdProjectVariableList = &cobra.Command{
	Use:   "list",
	Short: "list project variables",
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableList(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type variableListOptions struct {
	parentRef string
}

var variableListOpts variableListOptions

func init() {
	flags := cmdProjectVariableList.Flags()

	flags.StringVar(&variableListOpts.parentRef, "project", "", "project id or full path")

	if err := cmdProjectVariableList.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}

	cmdProjectVariable.AddCommand(cmdProjectVariableList)
}

func variableList(cmd *cobra.Command, ownertype string, args []string) error {
	if err := printVariables(ownertype, fmt.Sprintf("%s variables", ownertype), false, false); err != nil {
		return err
	}
	if err := printVariables(ownertype, "All variables (local and inherited)", true, true); err != nil {
		return err
	}
	return nil
}

func printVariables(ownertype, description string, tree, removeoverridden bool) error {

	var err error
	var variables []*gwapitypes.VariableResponse

	gwclient := gwclient.NewClient(gatewayURL, token)

	switch ownertype {
	case "project":
		variables, _, err = gwclient.GetProjectVariables(context.TODO(), variableListOpts.parentRef, tree, removeoverridden)
	case "projectgroup":
		variables, _, err = gwclient.GetProjectGroupVariables(context.TODO(), variableListOpts.parentRef, tree, removeoverridden)
	}
	if err != nil {
		return errors.Errorf("failed to list %s variables: %w", ownertype, err)
	}
	prettyJSON, err := json.MarshalIndent(variables, "", "\t")
	if err != nil {
		return errors.Errorf("failed to convert %s variables to json: %w", ownertype, err)
	}
	fmt.Printf("%s:\n%s\n", description, string(prettyJSON))
	return nil
}
