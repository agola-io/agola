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
	"github.com/spf13/cobra"
)

var cmdCompletionZsh = &cobra.Command{
	Use: "zsh",
	Run: func(cmd *cobra.Command, args []string) {
		if err := completionShell(cmd, args, "zsh"); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "generates zsh completion scripts",
	Long: `generates zsh completion scripts

To load zsh completion in the current session run:

  source <(agola completion zsh)

To configure your zsh shell to load completions for each session add the scripts to your ~/.zshrc file:

  echo 'source <(agola completion zsh)' >> ~/.zshrc

NOTE: the agola command must be in the user command search paths (PATH environment variable) or it is necessary to specify the absolute path of the agola binary (e.g. /your/path/agola).
`,
}

func init() {
	cmdCompletion.AddCommand(cmdCompletionZsh)
}
