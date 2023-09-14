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

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/notification/db"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	csclient "agola.io/agola/services/configstore/client"
	"agola.io/agola/services/notification/types"
	rsclient "agola.io/agola/services/runservice/client"
)

type NotificationService struct {
	log zerolog.Logger
	gc  *config.Config
	c   *config.Notification

	d  *db.DB
	lf lock.LockFactory

	runserviceClient  *rsclient.Client
	configstoreClient *csclient.Client

	u commitStatusUpdater
}

type commitStatusUpdater interface {
	updateCommitStatus(context.Context, *types.CommitStatus) (bool, error)
}

func NewNotificationService(ctx context.Context, log zerolog.Logger, gc *config.Config) (*NotificationService, error) {
	c := &gc.Notification

	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
	}

	sdb, err := sql.NewDB(c.DB.Type, c.DB.ConnString)
	if err != nil {
		return nil, errors.Wrapf(err, "new db error")
	}

	// We are currently using the db only for locking. No tables are created.

	var lf lock.LockFactory
	switch c.DB.Type {
	case sql.Sqlite3:
		ll := lock.NewLocalLocks()
		lf = lock.NewLocalLockFactory(ll)
	case sql.Postgres:
		lf = lock.NewPGLockFactory(sdb)
	default:
		return nil, errors.Errorf("unknown type %q", c.DB.Type)
	}

	d, err := db.NewDB(log, sdb)
	if err != nil {
		return nil, errors.Wrapf(err, "new db error")
	}

	dbm := manager.NewDBManager(log, d, lf)

	if err := common.SetupDB(ctx, dbm); err != nil {
		return nil, errors.Wrap(err, "failed to setup db")
	}

	configstoreClient := csclient.NewClient(c.ConfigstoreURL, c.ConfigstoreAPIToken)
	runserviceClient := rsclient.NewClient(c.RunserviceURL, c.RunserviceAPIToken)

	u := &GitSourceCommitStatusUpdater{
		configstoreClient: configstoreClient,
		c:                 c,
	}

	n := &NotificationService{
		log:               log,
		gc:                gc,
		c:                 c,
		d:                 d,
		lf:                lf,
		runserviceClient:  runserviceClient,
		configstoreClient: configstoreClient,
		u:                 u,
	}

	return n, nil
}

func (n *NotificationService) Run(ctx context.Context) error {
	go n.runEventsHandlerLoop(ctx)
	go n.RunWebhookDeliveriesHandlerLoop(ctx)
	go n.CommitStatusDeliveriesHandlerLoop(ctx)

	<-ctx.Done()
	n.log.Info().Msgf("notification service exiting")

	return nil
}
