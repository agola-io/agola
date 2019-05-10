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
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var cmdSleeper = &cobra.Command{
	Use:   "sleeper",
	Run:   sleeperRun,
	Short: "sleeper",
}

func init() {
	CmdToolbox.AddCommand(cmdSleeper)
}

func childsReaper() {
	var sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGCHLD)

	for {
		for range sigs {
			for {
				var wstatus syscall.WaitStatus
				if _, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG|syscall.WUNTRACED|syscall.WCONTINUED, nil); err == syscall.EINTR {
					continue
				}
				break
			}
		}
	}
}

func sleeperRun(cmd *cobra.Command, args []string) {
	go childsReaper()

	time.Sleep(100 * time.Hour)
	//c := make(chan struct{})
	//<-c
}
