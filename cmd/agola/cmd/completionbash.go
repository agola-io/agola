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

var cmdCompletionBash = &cobra.Command{
	Use: "bash",
	Run: func(cmd *cobra.Command, args []string) {
		if err := completionShell(cmd, args, "bash"); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "generates bash completion scripts",
	Long: `generates bash completion scripts

To load bash completion in the current session run:

  source <(agola completion bash)

To configure your bash shell to load completions for each session add the scripts to your ~/.bashrc file:

  echo 'source <(agola completion bash)' >> ~/.bashrc

or add the scripts to the /etc/bash_completion.d directory:

  agola completion bash > /etc/bash_completion.d/agola

NOTE: the agola command must be in the user command search paths (PATH environment variable) or it is necessary to specify the absolute path of the agola binary (e.g. /your/path/agola).
`,
}

func init() {
	cmdCompletion.AddCommand(cmdCompletionBash)
}
