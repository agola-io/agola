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
	"github.com/sorintlab/agola/internal/services/runservice/executor"
	rsscheduler "github.com/sorintlab/agola/internal/services/runservice/scheduler"
	"github.com/sorintlab/agola/internal/services/scheduler"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.etcd.io/etcd/embed"
)

var (
	// default gatewayURL
	gatewayURL = fmt.Sprintf("http://%s:%d", "localhost", 8000)
)

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
	embeddedEtcd        bool
	embeddedEtcdDataDir string
}

var serveOpts serveOptions

func init() {
	flags := cmdServe.PersistentFlags()

	flags.StringVar(&serveOpts.config, "config", "", "config file path")
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

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	c, err := config.Parse(serveOpts.config)
	if err != nil {
		return errors.Wrapf(err, "cannot parse config")
	}

	if serveOpts.embeddedEtcd {
		if err := embeddedEtcd(ctx); err != nil {
			return errors.Wrapf(err, "failed to start run service scheduler")
		}
	}

	rssched1, err := rsscheduler.NewScheduler(ctx, &c.RunServiceScheduler)
	if err != nil {
		return errors.Wrapf(err, "failed to start run service scheduler")
	}

	rsex1, err := executor.NewExecutor(&c.RunServiceExecutor)
	if err != nil {
		return errors.Wrapf(err, "failed to start run service executor")
	}

	cs, err := configstore.NewConfigStore(ctx, &c.ConfigStore)
	if err != nil {
		return errors.Wrapf(err, "failed to start config store")
	}

	sched1, err := scheduler.NewScheduler(&c.Scheduler)
	if err != nil {
		return errors.Wrapf(err, "failed to start scheduler")
	}

	gateway, err := gateway.NewGateway(&c.Gateway)
	if err != nil {
		return errors.Wrapf(err, "failed to start gateway")
	}

	errCh := make(chan error)

	go func() { errCh <- rsex1.Run(ctx) }()
	go func() { errCh <- rssched1.Run(ctx) }()
	go func() { errCh <- cs.Run(ctx) }()
	go func() { errCh <- gateway.Run(ctx) }()
	go func() { errCh <- sched1.Run(ctx) }()

	return <-errCh
}
