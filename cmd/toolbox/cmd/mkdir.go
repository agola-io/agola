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

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var cmdMkdir = &cobra.Command{
	Use:   "mkdir",
	Run:   mkdirRun,
	Short: "create the provided directories",
}

func init() {
	CmdToolbox.AddCommand(cmdMkdir)
}

func mkdirRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Fatalf("no directory name specified")
	}

	for _, dir := range args {
		// expand ~
		expDir, err := homedir.Expand(dir)
		if err != nil {
			log.Fatalf("failed to expand dir %q: %v", dir, err)
		}
		if err := os.MkdirAll(expDir, 0755); err != nil {
			log.Fatalf("failed to create directory %q: %v", expDir, err)
		}
	}
}
