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

func sleeperRun(cmd *cobra.Command, args []string) {
	time.Sleep(100 * time.Hour)
	//c := make(chan struct{})
	//<-c
}
