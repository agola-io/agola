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
	"log"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

var cmdShell = &cobra.Command{
	Use:   "shell",
	Run:   shellRun,
	Short: "reads data from stdin, saves it to a file and the executes it with the provided shell",
}

func init() {
	CmdToolbox.AddCommand(cmdShell)
}

func shellRun(cmd *cobra.Command, args []string) {
	filename, err := createFile(os.Stdin)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	env := os.Environ()

	args = append(args, filename)
	if err := syscall.Exec(args[0], args, env); err != nil {
		log.Fatalf("failed to exec: %v", err)
	}
}
