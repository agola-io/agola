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
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/handlers"
	"agola.io/agola/internal/services/notification/action"
	"agola.io/agola/internal/services/notification/api"
	"agola.io/agola/internal/services/notification/db"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	"agola.io/agola/services/notification/types"
	rsclient "agola.io/agola/services/runservice/client"
)

type NotificationService struct {
	log zerolog.Logger
	gc  *config.Config
	c   *config.Notification
	d   *db.DB
	lf  lock.LockFactory
	ah  *action.ActionHandler

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

	if c.DB.Type == sql.Sqlite3 {
		if err := os.MkdirAll(filepath.Dir(c.DB.ConnString), 0770); err != nil {
			return nil, errors.WithStack(err)
		}
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

	ah := action.NewActionHandler(log, d, lf)
	n.ah = ah

	return n, nil
}

func (n *NotificationService) setupDefaultRouter() http.Handler {
	runWebhookDeliveriesHandler := api.NewRunWebhookDeliveriesHandler(n.log, n.ah)
	runWebhookReliveryHandler := api.NewRunWebhookRedeliveryHandler(n.log, n.ah)
	commitStatusDeliveriesHandler := api.NewCommitStatusDeliveriesHandler(n.log, n.ah)
	commitStatusReliveryHandler := api.NewCommitStatusRedeliveryHandler(n.log, n.ah)

	authHandler := handlers.NewInternalAuthChecker(n.log, n.c.APIToken)

	router := mux.NewRouter().UseEncodedPath().SkipClean(true)
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath().SkipClean(true)

	apirouter.Use(authHandler)

	// don't return 404 on a call to an undefined handler but 400 to distinguish between a non existent resource and a wrong method
	apirouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	apirouter.Handle("/projects/{projectid}/runwebhookdeliveries", runWebhookDeliveriesHandler).Methods("GET")

	apirouter.Handle("/projects/{projectid}/runwebhookdeliveries/{runwebhookdeliveryid}/redelivery", runWebhookReliveryHandler).Methods("PUT")

	apirouter.Handle("/projects/{projectid}/commitstatusdeliveries", commitStatusDeliveriesHandler).Methods("GET")

	apirouter.Handle("/projects/{projectid}/commitstatusdeliveries/{commitstatusdeliveryid}/redelivery", commitStatusReliveryHandler).Methods("PUT")

	mainrouter := mux.NewRouter().UseEncodedPath().SkipClean(true)
	mainrouter.PathPrefix("/").Handler(router)

	// Return a bad request when it doesn't match any route
	mainrouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	return mainrouter
}

func (n *NotificationService) Run(ctx context.Context) error {
	for {
		if err := n.run(ctx); err != nil {
			n.log.Err(err).Msgf("run error")
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			n.log.Info().Msgf("notification service exiting")
			return nil
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) run(ctx context.Context) error {
	var tlsConfig *tls.Config
	if n.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(n.c.Web.TLSCertFile, n.c.Web.TLSKeyFile, "", false)
		if err != nil {
			n.log.Err(err).Send()
			return errors.WithStack(err)
		}
	}

	errCh := make(chan error, 100)
	var wg sync.WaitGroup

	util.GoWait(&wg, func() { n.runEventsHandlerLoop(ctx) })
	util.GoWait(&wg, func() { n.RunWebhookDeliveriesHandlerLoop(ctx) })
	util.GoWait(&wg, func() { n.CommitStatusDeliveriesHandlerLoop(ctx) })
	util.GoWait(&wg, func() { n.runWebhooksCleanerLoop(ctx, n.c.RunWebhookExpireInterval) })
	util.GoWait(&wg, func() { n.commitStatusesCleanerLoop(ctx, n.c.CommitStatusExpireInterval) })

	mainrouter := n.setupDefaultRouter()
	httpServer := http.Server{
		Addr:      n.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error, 1)
	util.GoWait(&wg, func() {
		if !n.c.Web.TLS {
			lerrCh <- httpServer.ListenAndServe()
		} else {
			lerrCh <- httpServer.ListenAndServeTLS("", "")
		}
	})

	var err error

	select {
	case <-ctx.Done():
		n.log.Info().Msgf("notification service run exiting")
	case err = <-lerrCh:
		if err != nil {
			n.log.Err(err).Msgf("http server listen error")
		}
	case err = <-errCh:
		if err != nil {
			n.log.Err(err).Send()
		}
	}

	httpServer.Close()
	wg.Wait()

	return errors.WithStack(err)
}
