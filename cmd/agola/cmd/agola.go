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

	"agola.io/agola/cmd"
	slog "agola.io/agola/internal/log"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
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
	Run: func(c *cobra.Command, args []string) {
		if err := c.Help(); err != nil {
			log.Fatal(err)
		}
	},
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
	if err := cmdAgola.Execute(); err != nil {
		os.Exit(1)
	}
}
