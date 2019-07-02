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
	"io"
	"log"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var cmdExpandDir = &cobra.Command{
	Use:   "expanddir",
	Run:   expanddirRun,
	Short: "create the provided directories",
}

func init() {
	CmdToolbox.AddCommand(cmdExpandDir)
}

func expanddirRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Fatalf("no directory name specified")
	}

	expDir, err := homedir.Expand(args[0])
	if err != nil {
		log.Fatalf("failed to expand dir %q: %v", expDir, err)
	}

	_, _ = io.WriteString(os.Stdout, expDir)
}
