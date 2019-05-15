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

package notification

import (
	"context"

	"github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/etcd"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/services/config"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

type NotificationService struct {
	gc *config.Config
	c  *config.Notification

	e *etcd.Store

	runserviceClient  *rsapi.Client
	configstoreClient *csapi.Client
}

func NewNotificationService(gc *config.Config) (*NotificationService, error) {
	c := &gc.Notification
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	e, err := common.NewEtcd(&c.Etcd, logger, "notification")
	if err != nil {
		return nil, err
	}

	configstoreClient := csapi.NewClient(c.ConfigstoreURL)
	runserviceClient := rsapi.NewClient(c.RunserviceURL)

	return &NotificationService{
		gc:                gc,
		c:                 c,
		e:                 e,
		runserviceClient:  runserviceClient,
		configstoreClient: configstoreClient,
	}, nil
}

func (n *NotificationService) Run(ctx context.Context) error {
	go n.runEventsHandlerLoop(ctx)

	select {
	case <-ctx.Done():
		log.Infof("notification service exiting")
		return nil
	}
}
