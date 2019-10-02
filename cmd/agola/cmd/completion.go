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
	"os"

	"github.com/spf13/cobra"
)

var cmdCompletion = &cobra.Command{
	Use:   "completion",
	Short: "completion",
}

func init() {
	cmdAgola.AddCommand(cmdCompletion)
}

func completionShell(cmd *cobra.Command, args []string, shell string) error {
	switch shell {
	case "bash":
		if err := cmdAgola.GenBashCompletion(os.Stdout); err != nil {
			return err
		}
	case "zsh":
		if err := cmdAgola.GenZshCompletion(os.Stdout); err != nil {
			return err
		}
	}
	return nil
}
