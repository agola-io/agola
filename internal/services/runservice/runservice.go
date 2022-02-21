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
	"path/filepath"
	"sync"
	"time"

	scommon "agola.io/agola/internal/common"
	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/api"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/readdb"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/mvcc/mvccpb"
)

// etcdPingerLoop periodically updates a key.
// This is used by watchers to inform the client of the current revision
// this is needed since if other users are updating other unwatched keys on
// etcd we won't be notified, not updating the known revisions
// TODO(sgotti) use upcoming etcd 3.4 watch RequestProgress???
func (s *Runservice) etcdPingerLoop(ctx context.Context) {
	for {
		if err := s.etcdPinger(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) etcdPinger(ctx context.Context) error {
	if _, err := s.e.Put(ctx, common.EtcdPingKey, []byte{}, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *Runservice) maintenanceModeWatcherLoop(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) {
	for {
		s.log.Debug().Msgf("maintenanceModeWatcherLoop")

		// at first watch restart from previous processed revision
		if err := s.maintenanceModeWatcher(ctx, runCtxCancel, maintenanceModeEnabled); err != nil {
			s.log.Err(err).Send()
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
	s.log.Info().Msgf("watcher: maintenance mode enabled: %t", maintenanceModeEnabled)
	resp, err := s.e.Get(ctx, common.EtcdMaintenanceKey, 0)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
	}

	if len(resp.Kvs) > 0 {
		s.log.Info().Msgf("maintenance mode key is present")
		if !maintenanceModeEnabled {
			runCtxCancel()
		}
	}

	revision := resp.Header.Revision

	wctx := etcdclientv3.WithRequireLeader(ctx)

	// restart from previous processed revision
	wch := s.e.Watch(wctx, common.EtcdMaintenanceKey, revision)

	for wresp := range wch {
		if wresp.Canceled {
			return errors.WithStack(wresp.Err())
		}

		for _, ev := range wresp.Events {
			switch ev.Type {
			case mvccpb.PUT:
				s.log.Info().Msgf("maintenance mode key set")
				if !maintenanceModeEnabled {
					runCtxCancel()
				}

			case mvccpb.DELETE:
				s.log.Info().Msgf("maintenance mode key removed")
				if maintenanceModeEnabled {
					runCtxCancel()
				}
			}
		}
	}

	return nil
}

type Runservice struct {
	log             zerolog.Logger
	c               *config.Runservice
	e               *etcd.Store
	ost             *objectstorage.ObjStorage
	dm              *datamanager.DataManager
	readDB          *readdb.ReadDB
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
	e, err := scommon.NewEtcd(&c.Etcd, log, "runservice")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s := &Runservice{
		log: log,
		c:   c,
		e:   e,
		ost: ost,
	}

	dmConf := &datamanager.DataManagerConfig{
		BasePath: "rundata",
		E:        e,
		OST:      ost,
		DataTypes: []string{
			string(common.DataTypeRun),
			string(common.DataTypeRunConfig),
			string(common.DataTypeRunCounter),
		},
	}
	dm, err := datamanager.NewDataManager(ctx, log, dmConf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s.dm = dm

	readDB, err := readdb.NewReadDB(ctx, log, filepath.Join(c.DataDir, "readdb"), e, ost, dm)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s.readDB = readDB

	ah := action.NewActionHandler(log, e, readDB, ost, dm)
	s.ah = ah

	return s, nil
}

func (s *Runservice) InitEtcd(ctx context.Context) error {
	// Create changegroup min revision if it doesn't exists
	cmp := []etcdclientv3.Cmp{}
	then := []etcdclientv3.Op{}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(common.EtcdChangeGroupMinRevisionKey), "=", 0))
	then = append(then, etcdclientv3.OpPut(common.EtcdChangeGroupMinRevisionKey, ""))
	txn := s.e.Client().Txn(ctx).If(cmp...).Then(then...)
	if _, err := txn.Commit(); err != nil {
		return errors.WithStack(etcd.FromEtcdError(err))
	}

	return nil
}

func (s *Runservice) setupDefaultRouter(etCh chan *types.ExecutorTask) http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah, s.e)
	exportHandler := api.NewExportHandler(s.log, s.ah)

	// executor dedicated api, only calls from executor should happen on these handlers
	executorStatusHandler := api.NewExecutorStatusHandler(s.log, s.e, s.ah)
	executorTaskStatusHandler := api.NewExecutorTaskStatusHandler(s.e, etCh)
	executorTaskHandler := api.NewExecutorTaskHandler(s.log, s.ah)
	executorTasksHandler := api.NewExecutorTasksHandler(s.log, s.ah)
	archivesHandler := api.NewArchivesHandler(s.log, s.ost)
	cacheHandler := api.NewCacheHandler(s.log, s.ost)
	cacheCreateHandler := api.NewCacheCreateHandler(s.log, s.ost)

	// api from clients
	executorDeleteHandler := api.NewExecutorDeleteHandler(s.log, s.ah)

	logsHandler := api.NewLogsHandler(s.log, s.e, s.ost, s.dm)
	logsDeleteHandler := api.NewLogsDeleteHandler(s.log, s.e, s.ost, s.dm)

	runHandler := api.NewRunHandler(s.log, s.e, s.dm, s.readDB)
	runByGroupHandler := api.NewRunByGroupHandler(s.log, s.e, s.dm, s.readDB)
	runTaskActionsHandler := api.NewRunTaskActionsHandler(s.log, s.ah)
	runsHandler := api.NewRunsHandler(s.log, s.readDB)
	runsByGroupHandler := api.NewRunsByGroupHandler(s.log, s.readDB)
	runActionsHandler := api.NewRunActionsHandler(s.log, s.ah)
	runCreateHandler := api.NewRunCreateHandler(s.log, s.ah)
	runEventsHandler := api.NewRunEventsHandler(s.log, s.e, s.ost, s.dm)

	changeGroupsUpdateTokensHandler := api.NewChangeGroupsUpdateTokensHandler(s.log, s.readDB)

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

	mainrouter := mux.NewRouter().UseEncodedPath().SkipClean(true)
	mainrouter.PathPrefix("/").Handler(router)

	// Return a bad request when it doesn't match any route
	mainrouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	return mainrouter
}

func (s *Runservice) setupMaintenanceRouter() http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah, s.e)
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

	resp, err := s.e.Get(ctx, common.EtcdMaintenanceKey, 0)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
	}

	maintenanceMode := false
	if len(resp.Kvs) > 0 {
		s.log.Info().Msgf("maintenance mode key is present")
		maintenanceMode = true
	}

	s.maintenanceMode = maintenanceMode
	s.dm.SetMaintenanceMode(maintenanceMode)
	s.ah.SetMaintenanceMode(maintenanceMode)

	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 100)
	var wg sync.WaitGroup
	dmReadyCh := make(chan struct{})

	var mainrouter http.Handler
	if s.maintenanceMode {
		mainrouter = s.setupMaintenanceRouter()
		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

	} else {
		ch := make(chan *types.ExecutorTask)
		mainrouter = s.setupDefaultRouter(ch)

		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

		// TODO(sgotti) wait for all goroutines exiting
		util.GoWait(&wg, func() { errCh <- s.dm.Run(ctx, dmReadyCh) })

		// wait for dm to be ready
		<-dmReadyCh

		for {
			err := s.InitEtcd(ctx)
			if err == nil {
				break
			}
			s.log.Err(err).Msgf("failed to initialize etcd")

			sleepCh := time.NewTimer(1 * time.Second).C
			select {
			case <-ctx.Done():
				return nil
			case <-sleepCh:
			}
		}

		util.GoWait(&wg, func() { errCh <- s.readDB.Run(ctx) })

		util.GoWait(&wg, func() { s.executorTasksCleanerLoop(ctx) })
		util.GoWait(&wg, func() { s.runsSchedulerLoop(ctx) })
		util.GoWait(&wg, func() { s.runTasksUpdaterLoop(ctx) })
		util.GoWait(&wg, func() { s.fetcherLoop(ctx) })
		util.GoWait(&wg, func() { s.finishedRunsArchiverLoop(ctx) })
		util.GoWait(&wg, func() { s.compactChangeGroupsLoop(ctx) })
		util.GoWait(&wg, func() { s.cacheCleanerLoop(ctx, s.c.RunCacheExpireInterval) })
		util.GoWait(&wg, func() { s.workspaceCleanerLoop(ctx, s.c.RunWorkspaceExpireInterval) })
		util.GoWait(&wg, func() { s.executorTaskUpdateHandler(ctx, ch) })
		util.GoWait(&wg, func() { s.etcdPingerLoop(ctx) })
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
	case err := <-errCh:
		if err != nil {
			s.log.Err(err).Send()
		}
	}

	cancel()
	httpServer.Close()
	wg.Wait()

	return errors.WithStack(err)
}
