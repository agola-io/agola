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
	"bufio"
	"flag"
	"log"
	"os"

	"agola.io/agola/internal/toolbox/unarchive"
	"github.com/mitchellh/go-homedir"

	"github.com/spf13/cobra"
)

var cmdUnarchive = &cobra.Command{
	Use:   "unarchive",
	Run:   unarchiveRun,
	Short: "Unarchive",
}

type unarchiveOptions struct {
	destDir       string
	overwrite     bool
	removeDestDir bool
}

var unarchiveOpts unarchiveOptions

func init() {
	flags := cmdUnarchive.PersistentFlags()

	flags.StringVar(&unarchiveOpts.destDir, "destdir", "", "destination directory")
	flags.BoolVar(&unarchiveOpts.overwrite, "overwrite", false, "overwrite destination files")
	flags.BoolVar(&unarchiveOpts.removeDestDir, "remove-destdir", false, "remove destination directory")

	CmdToolbox.AddCommand(cmdUnarchive)
}

func unarchiveRun(cmd *cobra.Command, args []string) {
	flag.Parse()

	// expand ~ in destdir
	destDir, err := homedir.Expand(unarchiveOpts.destDir)
	if err != nil {
		log.Fatalf("failed to expand dir %q: %v", unarchiveOpts.destDir, err)
	}

	br := bufio.NewReader(os.Stdin)

	if err := unarchive.Unarchive(br, destDir, unarchiveOpts.overwrite, unarchiveOpts.removeDestDir); err != nil {
		log.Fatalf("untar error: %v", err)
	}
}
