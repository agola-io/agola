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
	"net/url"

	"github.com/sorintlab/agola/cmd"
	slog "github.com/sorintlab/agola/internal/log"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

var token string

var cmdAgola = &cobra.Command{
	Use:     "agola",
	Short:   "agola",
	Version: cmd.Version,
	// just defined to make --version work
	PersistentPreRun: func(c *cobra.Command, args []string) {
		if err := parseGatewayURL(); err != nil {
			log.Fatalf("err: %v", err)
		}

		if agolaOpts.debug {
			level.SetLevel(zapcore.DebugLevel)
		}
	},
	Run: func(c *cobra.Command, args []string) { c.Help() },
}

type agolaOptions struct {
	gatewayURL string
	debug      bool
}

var agolaOpts agolaOptions

func parseGatewayURL() error {
	if agolaOpts.gatewayURL != "" {
		gatewayURL = agolaOpts.gatewayURL
	}
	if _, err := url.Parse(gatewayURL); err != nil {
		return errors.Errorf("cannot parse exposed gateway URL %q: %v", gatewayURL, err)
	}
	return nil
}

func init() {
	flags := cmdAgola.PersistentFlags()

	flags.StringVarP(&agolaOpts.gatewayURL, "gateway-url", "u", gatewayURL, "agola gateway exposed url")
	flags.StringVar(&token, "token", token, "api token")
	flags.BoolVarP(&agolaOpts.debug, "debug", "d", false, "debug")
}

func Execute() {
	cmdAgola.Execute()
}
