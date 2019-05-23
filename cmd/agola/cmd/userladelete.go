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
	"context"

	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdUserLADelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a user linkedaccount",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userLADelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userLADeleteOptions struct {
	userName string
	laID     string
}

var userLADeleteOpts userLADeleteOptions

func init() {
	flags := cmdUserLADelete.Flags()

	flags.StringVarP(&userLADeleteOpts.userName, "username", "n", "", "user name")
	flags.StringVar(&userLADeleteOpts.laID, "laid", "", "linked account id")

	cmdUserLADelete.MarkFlagRequired("username")
	cmdUserLADelete.MarkFlagRequired("laid")

	cmdUserLA.AddCommand(cmdUserLADelete)
}

func userLADelete(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	userName := userLADeleteOpts.userName
	laID := userLADeleteOpts.laID

	log.Infof("deleting linked account %q for user %q", laID, userName)
	_, err := gwclient.DeleteUserLA(context.TODO(), userName, laID)
	if err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}

	log.Infof("linked account %q for user %q deleted", laID, userName)

	return nil
}
