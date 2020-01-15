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

package notification

import (
	"context"

	"agola.io/agola/internal/common"
	"agola.io/agola/internal/etcd"
	slog "agola.io/agola/internal/log"
	"agola.io/agola/internal/services/config"
	csclient "agola.io/agola/services/configstore/client"
	rsclient "agola.io/agola/services/runservice/client"

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

	runserviceClient  *rsclient.Client
	configstoreClient *csclient.Client
}

func NewNotificationService(ctx context.Context, l *zap.Logger, gc *config.Config) (*NotificationService, error) {
	c := &gc.Notification

	if l != nil {
		logger = l
	}
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}
	log = logger.Sugar()

	e, err := common.NewEtcd(&c.Etcd, logger, "notification")
	if err != nil {
		return nil, err
	}

	configstoreClient := csclient.NewClient(c.ConfigstoreURL)
	runserviceClient := rsclient.NewClient(c.RunserviceURL)

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

	<-ctx.Done()
	log.Infof("notification service exiting")

	return nil
}
