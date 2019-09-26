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

var cmdProjectVariableUpdate = &cobra.Command{
	Use:   "update",
	Short: "update a project variable",
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableUpdate(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type variableUpdateOptions struct {
	parentRef string
	name      string
	newName   string
	file      string
}

var variableUpdateOpts variableUpdateOptions

func init() {
	flags := cmdProjectVariableUpdate.Flags()

	flags.StringVar(&variableUpdateOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&variableUpdateOpts.name, "name", "n", "", "variable name")
	flags.StringVarP(&variableUpdateOpts.newName, "new-name", "", "", "variable new name")
	flags.StringVarP(&variableUpdateOpts.file, "file", "f", "", `yaml file containing the variable definition (use "-" to read from stdin)`)

	if err := cmdProjectVariableUpdate.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectVariableUpdate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectVariableUpdate.MarkFlagRequired("file"); err != nil {
		log.Fatal(err)
	}

	cmdProjectVariable.AddCommand(cmdProjectVariableUpdate)
}

func variableUpdate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// "github.com/ghodss/yaml" doesn't provide a streaming decoder
	var data []byte
	var err error
	if variableUpdateOpts.file == "-" {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		data, err = ioutil.ReadFile(variableUpdateOpts.file)
		if err != nil {
			return err
		}
	}

	var values []VariableValue
	if err := yaml.Unmarshal(data, &values); err != nil {
		log.Fatalf("failed to unmarshall values: %v", err)
	}
	rvalues := []gwapitypes.VariableValueRequest{}
	for _, value := range values {
		rvalues = append(rvalues, gwapitypes.VariableValueRequest{
			SecretName: value.SecretName,
			SecretVar:  value.SecretVar,
			When:       value.When.ToWhen(),
		})
	}
	req := &gwapitypes.UpdateVariableRequest{
		Name:   variableUpdateOpts.name,
		Values: rvalues,
	}

	flags := cmd.Flags()
	if flags.Changed("new-name") {
		req.Name = variableUpdateOpts.newName
	}

	switch ownertype {
	case "project":
		log.Infof("updating project variable")
		variable, _, err := gwclient.UpdateProjectVariable(context.TODO(), variableUpdateOpts.parentRef, variableUpdateOpts.name, req)
		if err != nil {
			return errors.Errorf("failed to update project variable: %w", err)
		}
		log.Infof("project variable %q updated, ID: %q", variable.Name, variable.ID)
	case "projectgroup":
		log.Infof("updating project group variable")
		variable, _, err := gwclient.UpdateProjectGroupVariable(context.TODO(), variableUpdateOpts.parentRef, variableUpdateOpts.name, req)
		if err != nil {
			return errors.Errorf("failed to update project group variable: %w", err)
		}
		log.Infof("project group variable %q updated, ID: %q", variable.Name, variable.ID)
	}

	return nil
}
