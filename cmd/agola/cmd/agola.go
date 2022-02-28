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
	"net/url"
	"os"
	"time"

	"agola.io/agola/cmd"
	"agola.io/agola/internal/errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var token string

func init() {
	cw := zerolog.ConsoleWriter{
		Out:                 os.Stderr,
		TimeFormat:          time.RFC3339Nano,
		FormatErrFieldValue: errors.FormatErrFieldValue,
	}

	zerolog.TimeFieldFormat = time.RFC3339Nano

	log.Logger = log.With().Stack().Caller().Logger().Level(zerolog.InfoLevel).Output(cw)
}

var cmdAgola = &cobra.Command{
	Use:     "agola",
	Short:   "agola",
	Version: cmd.Version,
	// just defined to make --version work
	PersistentPreRun: func(c *cobra.Command, args []string) {
		if err := parseGatewayURL(); err != nil {
			log.Fatal().Err(err).Send()
		}

		if agolaOpts.debug {
			log.Logger = log.Level(zerolog.DebugLevel)
		}
		if agolaOpts.detailedErrors {
			zerolog.ErrorMarshalFunc = errors.ErrorMarshalFunc
		}
	},
	Run: func(c *cobra.Command, args []string) {
		if err := c.Help(); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type agolaOptions struct {
	gatewayURL     string
	debug          bool
	detailedErrors bool
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
	flags.BoolVar(&agolaOpts.detailedErrors, "detailed-errors", false, "enabled detailed errors logging")
}

func Execute() {
	if err := cmdAgola.Execute(); err != nil {
		os.Exit(1)
	}
}
