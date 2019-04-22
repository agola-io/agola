// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

type ExecData struct {
	Cmd        []string          `json:"cmd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
}

var cmdExec = &cobra.Command{
	Use:   "exec",
	Run:   execRun,
	Short: "executes the provided command using the provided working dir and environment",
}

type execOptions struct {
	env        string
	workingDir string
}

var execOpts execOptions

func init() {
	flags := cmdExec.PersistentFlags()

	flags.StringVarP(&execOpts.workingDir, "workingdir", "w", "", "working directory")
	flags.StringVarP(&execOpts.env, "env", "e", "", "environment (as json object)")

	CmdToolbox.AddCommand(cmdExec)
}

func execRun(cmd *cobra.Command, args []string) {
	env := os.Environ()
	if execOpts.env != "" {
		envmap := map[string]string{}
		if err := json.Unmarshal([]byte(execOpts.env), &envmap); err != nil {
			log.Fatalf("failed to unmarshal env: %v", err)
		}
		// also set current env so exec.LookPath will use the provided env
		for n, v := range envmap {
			env = append(env, fmt.Sprintf("%s=%s", n, v))
			if err := os.Setenv(n, v); err != nil {
				log.Fatalf("failed to set env: %v", err)
			}
		}
	}

	if execOpts.workingDir != "" {
		if err := os.Chdir(execOpts.workingDir); err != nil {
			log.Fatalf("failed to change working dir to %q", execOpts.workingDir)
		}
	}

	p, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatalf("failed to find executable %q: %v", args[0], err)
	}
	if err := syscall.Exec(p, args, env); err != nil {
		log.Fatalf("failed to exec: %v", err)
	}
}
