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
	"fmt"

	"github.com/sorintlab/agola/cmd"
	"github.com/sorintlab/agola/internal/services/config"
	"github.com/sorintlab/agola/internal/services/configstore"
	"github.com/sorintlab/agola/internal/services/gateway"
	"github.com/sorintlab/agola/internal/services/gitserver"
	"github.com/sorintlab/agola/internal/services/runservice/executor"
	rsexecutor "github.com/sorintlab/agola/internal/services/runservice/executor"
	rsscheduler "github.com/sorintlab/agola/internal/services/runservice/scheduler"
	"github.com/sorintlab/agola/internal/services/scheduler"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.etcd.io/etcd/embed"
)

var (
	// default gatewayURL
	gatewayURL = fmt.Sprintf("http://%s:%d", "localhost", 8000)
)

var componentsNames = []string{
	"all",
	"gateway",
	"scheduler",
	"runservicescheduler",
	"runserviceexecutor",
	"configstore",
	"gitserver",
}

var cmdServe = &cobra.Command{
	Use:     "serve",
	Short:   "serve",
	Version: cmd.Version,
	Run: func(cmd *cobra.Command, args []string) {
		if err := serve(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type serveOptions struct {
	config              string
	components          []string
	embeddedEtcd        bool
	embeddedEtcdDataDir string
}

var serveOpts serveOptions

func init() {
	flags := cmdServe.PersistentFlags()

	flags.StringVar(&serveOpts.config, "config", "./config.yml", "config file path")
	flags.StringSliceVar(&serveOpts.components, "components", []string{}, `list of components to start (specify "all" to start all components)`)
	flags.BoolVar(&serveOpts.embeddedEtcd, "embedded-etcd", false, "start and use an embedded etcd, only for testing purpose")
	flags.StringVar(&serveOpts.embeddedEtcdDataDir, "embedded-etcd-data-dir", "/tmp/agola/etcd", "embedded etcd data dir, only for testing purpose")

	cmdServe.MarkFlagRequired("config")

	cmdAgola.AddCommand(cmdServe)
}

func embeddedEtcd(ctx context.Context) error {
	cfg := embed.NewConfig()
	cfg.Dir = serveOpts.embeddedEtcdDataDir
	cfg.Logger = "zap"
	cfg.LogOutputs = []string{"stderr"}

	log.Infof("starting embedded etcd server")
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return err
	}

	go func() {
		select {
		case <-e.Server.ReadyNotify():
			log.Infof("embedded etcd server is ready")
		}
		select {
		case <-ctx.Done():
			log.Infof("stopping embedded etcd server")
			e.Close()
		}
	}()

	return nil
}

func isComponentEnabled(name string) bool {
	if util.StringInSlice(serveOpts.components, "all") {
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
			return errors.Errorf("unkown component name %q", ec)
		}
	}

	c, err := config.Parse(serveOpts.config)
	if err != nil {
		return errors.Wrapf(err, "config error")
	}

	if serveOpts.embeddedEtcd {
		if err := embeddedEtcd(ctx); err != nil {
			return errors.Wrapf(err, "failed to start run service scheduler")
		}
	}

	var rssched *rsscheduler.Scheduler
	if isComponentEnabled("runservicescheduler") {
		rssched, err = rsscheduler.NewScheduler(ctx, &c.RunServiceScheduler)
		if err != nil {
			return errors.Wrapf(err, "failed to start run service scheduler")
		}
	}

	var rsex *rsexecutor.Executor
	if isComponentEnabled("runserviceexecutor") {
		rsex, err = executor.NewExecutor(&c.RunServiceExecutor)
		if err != nil {
			return errors.Wrapf(err, "failed to start run service executor")
		}
	}

	var cs *configstore.Configstore
	if isComponentEnabled("configstore") {
		cs, err = configstore.NewConfigstore(ctx, &c.Configstore)
		if err != nil {
			return errors.Wrapf(err, "failed to start config store")
		}
	}

	var sched *scheduler.Scheduler
	if isComponentEnabled("scheduler") {
		sched, err = scheduler.NewScheduler(&c.Scheduler)
		if err != nil {
			return errors.Wrapf(err, "failed to start scheduler")
		}
	}

	var gw *gateway.Gateway
	if isComponentEnabled("gateway") {
		gw, err = gateway.NewGateway(c)
		if err != nil {
			return errors.Wrapf(err, "failed to start gateway")
		}
	}

	var gs *gitserver.GitServer
	if isComponentEnabled("gitserver") {
		gs, err = gitserver.NewGitServer(&c.GitServer)
		if err != nil {
			return errors.Wrapf(err, "failed to start git server")
		}
	}

	errCh := make(chan error)

	if rssched != nil {
		go func() { errCh <- rssched.Run(ctx) }()
	}
	if rsex != nil {
		go func() { errCh <- rsex.Run(ctx) }()
	}
	if cs != nil {
		go func() { errCh <- cs.Run(ctx) }()
	}
	if sched != nil {
		go func() { errCh <- sched.Run(ctx) }()
	}
	if gw != nil {
		go func() { errCh <- gw.Run(ctx) }()
	}
	if gs != nil {
		go func() { errCh <- gs.Run(ctx) }()
	}

	return <-errCh
}
