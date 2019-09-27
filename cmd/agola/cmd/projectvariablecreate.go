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

	config "agola.io/agola/internal/config"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectVariableCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project variable",
	Long: `create a project variable

The variable values should be provided by a yaml document. Examples:

- secret_name: secret01
  secret_var: var01
  when:
    branch: master
    tag:
      - v1.x
      - v2.x
- secret_name: secret02
  secret_var: data02
  when:
    ref:
      include:
        - '#/refs/pull/.*#'
        - '#/refs/heads/devel.*#'
      exclude: /refs/heads/develop

The above yaml document defines a variable that can have two different values depending on the first matching condition.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableCreate(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type variableCreateOptions struct {
	parentRef string
	name      string
	file      string
}

var variableCreateOpts variableCreateOptions

func init() {
	flags := cmdProjectVariableCreate.Flags()

	flags.StringVar(&variableCreateOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&variableCreateOpts.name, "name", "n", "", "variable name")
	flags.StringVarP(&variableCreateOpts.file, "file", "f", "", `yaml file containing the variable definition (use "-" to read from stdin)`)

	if err := cmdProjectVariableCreate.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectVariableCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectVariableCreate.MarkFlagRequired("file"); err != nil {
		log.Fatal(err)
	}

	cmdProjectVariable.AddCommand(cmdProjectVariableCreate)
}

type VariableValue struct {
	SecretName string `json:"secret_name,omitempty"`
	SecretVar  string `json:"secret_var,omitempty"`

	When *config.When `json:"when,omitempty"`
}

func variableCreate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// "github.com/ghodss/yaml" doesn't provide a streaming decoder
	var data []byte
	var err error
	if variableCreateOpts.file == "-" {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		data, err = ioutil.ReadFile(variableCreateOpts.file)
		if err != nil {
			return err
		}
	}

	var values []VariableValue
	if err := yaml.Unmarshal(data, &values); err != nil {
		log.Fatalf("failed to unmarshal values: %v", err)
	}
	rvalues := []gwapitypes.VariableValueRequest{}
	for _, value := range values {
		rvalues = append(rvalues, gwapitypes.VariableValueRequest{
			SecretName: value.SecretName,
			SecretVar:  value.SecretVar,
			When:       value.When.ToWhen(),
		})
	}
	req := &gwapitypes.CreateVariableRequest{
		Name:   variableCreateOpts.name,
		Values: rvalues,
	}

	switch ownertype {
	case "project":
		log.Infof("creating project variable")
		variable, _, err := gwclient.CreateProjectVariable(context.TODO(), variableCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project variable: %w", err)
		}
		log.Infof("project variable %q created, ID: %q", variable.Name, variable.ID)
	case "projectgroup":
		log.Infof("creating project group variable")
		variable, _, err := gwclient.CreateProjectGroupVariable(context.TODO(), variableCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project group variable: %w", err)
		}
		log.Infof("project group variable %q created, ID: %q", variable.Name, variable.ID)
	}

	return nil
}
