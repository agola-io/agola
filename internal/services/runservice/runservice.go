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

package runservice

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	scommon "agola.io/agola/internal/common"
	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/lock"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/api"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func (s *Runservice) maintenanceModeWatcherLoop(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) {
	s.log.Info().Msgf("maintenance mode watcher: maintenance mode enabled: %t", maintenanceModeEnabled)

	for {
		s.log.Debug().Msgf("maintenanceModeWatcherLoop")

		// at first watch restart from previous processed revision
		if err := s.maintenanceModeWatcher(ctx, runCtxCancel, maintenanceModeEnabled); err != nil {
			s.log.Err(err).Msgf("maintenance mode watcher error")
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) maintenanceModeWatcher(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) error {
	maintenanceEnabled, err := s.ah.IsMaintenanceEnabled(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if maintenanceEnabled != maintenanceModeEnabled {
		s.log.Info().Msgf("maintenance mode changed to %t", maintenanceEnabled)
		runCtxCancel()
	}

	return nil
}

type Runservice struct {
	log             zerolog.Logger
	c               *config.Runservice
	ost             *objectstorage.ObjStorage
	d               *db.DB
	lf              lock.LockFactory
	ah              *action.ActionHandler
	maintenanceMode bool
}

func NewRunservice(ctx context.Context, log zerolog.Logger, c *config.Runservice) (*Runservice, error) {
	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
	}

	ost, err := scommon.NewObjectStorage(&c.ObjectStorage)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s := &Runservice{
		log: log,
		c:   c,
		ost: ost,
	}

	sdb, err := sql.NewDB(c.DB.Type, c.DB.ConnString)
	if err != nil {
		return nil, errors.Wrapf(err, "new db error")
	}

	d, err := db.NewDB(log, sdb)
	if err != nil {
		return nil, errors.Wrapf(err, "new db error")
	}
	s.d = d

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
	s.lf = lf

	if err := idb.Setup(ctx, log, d, lf); err != nil {
		return nil, errors.Wrapf(err, "create db error")
	}

	ah := action.NewActionHandler(log, d, ost, lf)
	s.ah = ah

	return s, nil
}

func (s *Runservice) setupDefaultRouter(etCh chan string) http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah)
	exportHandler := api.NewExportHandler(s.log, s.ah)
	importHandler := api.NewImportHandler(s.log, s.ah)

	// executor dedicated api, only calls from executor should happen on these handlers
	executorStatusHandler := api.NewExecutorStatusHandler(s.log, s.d, s.ah)
	executorTaskStatusHandler := api.NewExecutorTaskStatusHandler(s.log, s.d, etCh)
	executorTaskHandler := api.NewExecutorTaskHandler(s.log, s.ah)
	executorTasksHandler := api.NewExecutorTasksHandler(s.log, s.ah)
	archivesHandler := api.NewArchivesHandler(s.log, s.ost)
	cacheHandler := api.NewCacheHandler(s.log, s.ost)
	cacheCreateHandler := api.NewCacheCreateHandler(s.log, s.ost)

	// api from clients
	executorDeleteHandler := api.NewExecutorDeleteHandler(s.log, s.d)

	logsHandler := api.NewLogsHandler(s.log, s.d, s.ost)
	logsDeleteHandler := api.NewLogsDeleteHandler(s.log, s.d, s.ost)

	runHandler := api.NewRunHandler(s.log, s.d, s.ah)
	runByGroupHandler := api.NewRunByGroupHandler(s.log, s.d, s.ah)
	runTaskActionsHandler := api.NewRunTaskActionsHandler(s.log, s.ah)
	runsHandler := api.NewRunsHandler(s.log, s.d, s.ah)
	runsByGroupHandler := api.NewRunsByGroupHandler(s.log, s.d, s.ah)
	runActionsHandler := api.NewRunActionsHandler(s.log, s.ah)
	runCreateHandler := api.NewRunCreateHandler(s.log, s.ah)
	runEventsHandler := api.NewRunEventsHandler(s.log, s.d, s.ost)

	changeGroupsUpdateTokensHandler := api.NewChangeGroupsUpdateTokensHandler(s.log, s.d, s.ah)

	router := mux.NewRouter().UseEncodedPath().SkipClean(true)
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath().SkipClean(true)

	// don't return 404 on a call to an undefined handler but 400 to distinguish between a non existent resource and a wrong method
	apirouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	apirouter.Handle("/executor/{executorid}", executorStatusHandler).Methods("POST")
	apirouter.Handle("/executor/{executorid}", executorDeleteHandler).Methods("DELETE")
	apirouter.Handle("/executor/{executorid}/tasks", executorTasksHandler).Methods("GET")
	apirouter.Handle("/executor/{executorid}/tasks/{taskid}", executorTaskHandler).Methods("GET")
	apirouter.Handle("/executor/{executorid}/tasks/{taskid}", executorTaskStatusHandler).Methods("POST")
	apirouter.Handle("/executor/archives", archivesHandler).Methods("GET")
	apirouter.Handle("/executor/caches/{key}", cacheHandler).Methods("HEAD")
	apirouter.Handle("/executor/caches/{key}", cacheHandler).Methods("GET")
	apirouter.Handle("/executor/caches/{key}", cacheCreateHandler).Methods("POST")

	apirouter.Handle("/logs", logsHandler).Methods("GET")
	apirouter.Handle("/logs", logsDeleteHandler).Methods("DELETE")

	apirouter.Handle("/runs/events", runEventsHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}", runHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", runActionsHandler).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", runTaskActionsHandler).Methods("PUT")

	apirouter.Handle("/runs/group/{group}/{runcounter}", runByGroupHandler).Methods("GET")
	apirouter.Handle("/runs/group/{group}", runsByGroupHandler).Methods("GET")

	apirouter.Handle("/runs", runsHandler).Methods("GET")
	apirouter.Handle("/runs", runCreateHandler).Methods("POST")

	apirouter.Handle("/changegroups", changeGroupsUpdateTokensHandler).Methods("GET")

	apirouter.Handle("/maintenance", maintenanceModeHandler).Methods("PUT", "DELETE")

	apirouter.Handle("/export", exportHandler).Methods("GET")
	apirouter.Handle("/import", importHandler).Methods("POST")

	mainrouter := mux.NewRouter().UseEncodedPath().SkipClean(true)
	mainrouter.PathPrefix("/").Handler(router)

	// Return a bad request when it doesn't match any route
	mainrouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	return mainrouter
}

func (s *Runservice) setupMaintenanceRouter() http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah)
	exportHandler := api.NewExportHandler(s.log, s.ah)
	importHandler := api.NewImportHandler(s.log, s.ah)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/maintenance", maintenanceModeHandler).Methods("PUT", "DELETE")

	apirouter.Handle("/export", exportHandler).Methods("GET")
	apirouter.Handle("/import", importHandler).Methods("POST")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(router)

	return mainrouter
}

func (s *Runservice) Run(ctx context.Context) error {
	for {
		if err := s.run(ctx); err != nil {
			s.log.Err(err).Msgf("run error")
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			s.log.Info().Msgf("runservice exiting")
			return nil
		case <-sleepCh:
		}
	}
}

func (s *Runservice) run(ctx context.Context) error {
	var tlsConfig *tls.Config
	if s.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(s.c.Web.TLSCertFile, s.c.Web.TLSKeyFile, "", false)
		if err != nil {
			s.log.Err(err).Send()
			return errors.WithStack(err)
		}
	}

	maintenanceEnabled, err := s.ah.IsMaintenanceEnabled(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	s.maintenanceMode = maintenanceEnabled
	s.ah.SetMaintenanceMode(s.maintenanceMode)

	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 100)
	var wg sync.WaitGroup

	var mainrouter http.Handler
	if s.maintenanceMode {
		mainrouter = s.setupMaintenanceRouter()
		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

	} else {
		ch := make(chan string)
		mainrouter = s.setupDefaultRouter(ch)

		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

		// TODO(sgotti) wait for all goroutines exiting

		util.GoWait(&wg, func() { s.executorTasksCleanerLoop(ctx) })
		util.GoWait(&wg, func() { s.runsSchedulerLoop(ctx) })
		util.GoWait(&wg, func() { s.runTasksUpdaterLoop(ctx) })
		util.GoWait(&wg, func() { s.fetcherLoop(ctx) })
		util.GoWait(&wg, func() { s.finishedRunsArchiverLoop(ctx) })
		util.GoWait(&wg, func() { s.compactChangeGroupsLoop(ctx) })
		util.GoWait(&wg, func() { s.cacheCleanerLoop(ctx, s.c.RunCacheExpireInterval) })
		util.GoWait(&wg, func() { s.workspaceCleanerLoop(ctx, s.c.RunWorkspaceExpireInterval) })
		util.GoWait(&wg, func() { s.executorTaskUpdateHandler(ctx, ch) })
	}

	httpServer := http.Server{
		Addr:      s.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error, 1)
	util.GoWait(&wg, func() {
		if !s.c.Web.TLS {
			lerrCh <- httpServer.ListenAndServe()
		} else {
			lerrCh <- httpServer.ListenAndServeTLS("", "")
		}
	})

	select {
	case <-ctx.Done():
		s.log.Info().Msgf("runservice run exiting")
	case err = <-lerrCh:
		if err != nil {
			s.log.Err(err).Msgf("http server listen error")
		}
	case err = <-errCh:
		if err != nil {
			s.log.Err(err).Send()
		}
	}

	cancel()
	httpServer.Close()
	wg.Wait()

	return errors.WithStack(err)
}
