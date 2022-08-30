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
	"context"
	"fmt"

	"agola.io/agola/cmd"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/configstore"
	"agola.io/agola/internal/services/executor"
	rsexecutor "agola.io/agola/internal/services/executor"
	"agola.io/agola/internal/services/gateway"
	"agola.io/agola/internal/services/gitserver"
	"agola.io/agola/internal/services/notification"
	rsscheduler "agola.io/agola/internal/services/runservice"
	"agola.io/agola/internal/services/scheduler"
	"agola.io/agola/internal/util"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	// default gatewayURL
	gatewayURL = fmt.Sprintf("http://%s:%d", "localhost", 8000)
)

var componentsNames = []string{
	"all-base",
	"gateway",
	"scheduler",
	"notification",
	"runservice",
	"executor",
	"configstore",
	"gitserver",
}

var cmdServe = &cobra.Command{
	Use:     "serve",
	Short:   "serve",
	Version: cmd.Version,
	Run: func(cmd *cobra.Command, args []string) {
		if err := serve(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type serveOptions struct {
	config     string
	components []string
}

var serveOpts serveOptions

func init() {
	flags := cmdServe.Flags()

	flags.StringVar(&serveOpts.config, "config", "./config.yml", "config file path")
	flags.StringSliceVar(&serveOpts.components, "components", []string{}, `list of components to start. Specify "all-base" to start all base components (excluding the executor).`)

	if err := cmdServe.MarkFlagRequired("components"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdAgola.AddCommand(cmdServe)
}

func isComponentEnabled(name string) bool {
	if util.StringInSlice(serveOpts.components, "all-base") && name != "executor" {
		return true
	}
	return util.StringInSlice(serveOpts.components, name)
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if len(serveOpts.components) == 0 {
		return errors.Errorf("no enabled components")
	}
	for _, ec := range serveOpts.components {
		if !util.StringInSlice(componentsNames, ec) {
			return errors.Errorf("unknown component name %q", ec)
		}
	}

	c, err := config.Parse(serveOpts.config, serveOpts.components)
	if err != nil {
		return errors.Wrapf(err, "config error")
	}

	var rs *rsscheduler.Runservice
	if isComponentEnabled("runservice") {
		rs, err = rsscheduler.NewRunservice(ctx, log.Logger, &c.Runservice)
		if err != nil {
			return errors.Wrapf(err, "failed to start run service scheduler")
		}
	}

	var ex *rsexecutor.Executor
	if isComponentEnabled("executor") {
		ex, err = executor.NewExecutor(ctx, log.Logger, &c.Executor)
		if err != nil {
			return errors.Wrapf(err, "failed to start run service executor")
		}
	}

	var cs *configstore.Configstore
	if isComponentEnabled("configstore") {
		cs, err = configstore.NewConfigstore(ctx, log.Logger, &c.Configstore)
		if err != nil {
			return errors.Wrapf(err, "failed to start config store")
		}
	}

	var sched *scheduler.Scheduler
	if isComponentEnabled("scheduler") {
		sched, err = scheduler.NewScheduler(ctx, log.Logger, &c.Scheduler)
		if err != nil {
			return errors.Wrapf(err, "failed to start scheduler")
		}
	}

	var ns *notification.NotificationService
	if isComponentEnabled("notification") {
		ns, err = notification.NewNotificationService(ctx, log.Logger, c)
		if err != nil {
			return errors.Wrapf(err, "failed to start notification service")
		}
	}

	var gw *gateway.Gateway
	if isComponentEnabled("gateway") {
		gw, err = gateway.NewGateway(ctx, log.Logger, c)
		if err != nil {
			return errors.Wrapf(err, "failed to start gateway")
		}
	}

	var gs *gitserver.Gitserver
	if isComponentEnabled("gitserver") {
		gs, err = gitserver.NewGitserver(ctx, log.Logger, &c.Gitserver)
		if err != nil {
			return errors.Wrapf(err, "failed to start git server")
		}
	}

	errCh := make(chan error)

	if rs != nil {
		go func() { errCh <- rs.Run(ctx) }()
	}
	if ex != nil {
		go func() { errCh <- ex.Run(ctx) }()
	}
	if cs != nil {
		go func() { errCh <- cs.Run(ctx) }()
	}
	if sched != nil {
		go func() { errCh <- sched.Run(ctx) }()
	}
	if ns != nil {
		go func() { errCh <- ns.Run(ctx) }()
	}
	if gw != nil {
		go func() { errCh <- gw.Run(ctx) }()
	}
	if gs != nil {
		go func() { errCh <- gs.Run(ctx) }()
	}

	return <-errCh
}
