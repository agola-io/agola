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
