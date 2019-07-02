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

	"agola.io/agola/cmd"

	"github.com/spf13/cobra"
)

var CmdToolbox = &cobra.Command{
	Use:     "toolbox",
	Short:   "toolbox",
	Version: cmd.Version,
	// just defined to make --version work
	Run: func(c *cobra.Command, args []string) {
		if err := c.Help(); err != nil {
			log.Fatal(err)
		}
	},
}

func Execute() {
	if err := CmdToolbox.Execute(); err != nil {
		os.Exit(1)
	}
}
