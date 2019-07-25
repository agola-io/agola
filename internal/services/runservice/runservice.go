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
	"time"

	scommon "agola.io/agola/internal/common"
	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/api"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/readdb"
	"agola.io/agola/internal/services/runservice/types"
	"agola.io/agola/internal/util"

	"github.com/gorilla/mux"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.uber.org/zap/zapcore"
)

// etcdPingerLoop periodically updates a key.
// This is used by watchers to inform the client of the current revision
// this is needed since if other users are updating other unwatched keys on
// etcd we won't be notified, not updating the known revisions
// TODO(sgotti) use upcoming etcd 3.4 watch RequestProgress???
func (s *Runservice) etcdPingerLoop(ctx context.Context) {
	for {
		if err := s.etcdPinger(ctx); err != nil {
			log.Errorf("err: %+v", err)
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
		return err
	}
	return nil
}

type Runservice struct {
	c      *config.Runservice
	e      *etcd.Store
	ost    *objectstorage.ObjStorage
	dm     *datamanager.DataManager
	readDB *readdb.ReadDB
	ah     *action.ActionHandler
}

func NewRunservice(ctx context.Context, c *config.Runservice) (*Runservice, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	ost, err := scommon.NewObjectStorage(&c.ObjectStorage)
	if err != nil {
		return nil, err
	}
	e, err := scommon.NewEtcd(&c.Etcd, logger, "runservice")
	if err != nil {
		return nil, err
	}

	s := &Runservice{
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
	dm, err := datamanager.NewDataManager(ctx, logger, dmConf)
	if err != nil {
		return nil, err
	}
	s.dm = dm

	readDB, err := readdb.NewReadDB(ctx, logger, filepath.Join(c.DataDir, "readdb"), e, ost, dm)
	if err != nil {
		return nil, err
	}
	s.readDB = readDB

	ah := action.NewActionHandler(logger, e, readDB, ost, dm)
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
		return etcd.FromEtcdError(err)
	}

	return nil
}

func (s *Runservice) Run(ctx context.Context) error {
	errCh := make(chan error)
	dmReadyCh := make(chan struct{})

	go func() { errCh <- s.dm.Run(ctx, dmReadyCh) }()

	// wait for dm to be ready
	<-dmReadyCh

	for {
		err := s.InitEtcd(ctx)
		if err == nil {
			break
		}
		log.Errorf("failed to initialize etcd: %+v", err)
		time.Sleep(1 * time.Second)
	}

	go func() { errCh <- s.readDB.Run(ctx) }()

	ch := make(chan *types.ExecutorTask)

	// executor dedicated api, only calls from executor should happen on these handlers
	executorStatusHandler := api.NewExecutorStatusHandler(logger, s.e, s.ah)
	executorTaskStatusHandler := api.NewExecutorTaskStatusHandler(s.e, ch)
	executorTaskHandler := api.NewExecutorTaskHandler(s.e)
	executorTasksHandler := api.NewExecutorTasksHandler(s.e)
	archivesHandler := api.NewArchivesHandler(logger, s.ost)
	cacheHandler := api.NewCacheHandler(logger, s.ost)
	cacheCreateHandler := api.NewCacheCreateHandler(logger, s.ost)

	// api from clients
	executorDeleteHandler := api.NewExecutorDeleteHandler(logger, s.ah)

	logsHandler := api.NewLogsHandler(logger, s.e, s.ost, s.dm)

	runHandler := api.NewRunHandler(logger, s.e, s.dm, s.readDB)
	runTaskActionsHandler := api.NewRunTaskActionsHandler(logger, s.ah)
	runsHandler := api.NewRunsHandler(logger, s.readDB)
	runActionsHandler := api.NewRunActionsHandler(logger, s.ah)
	runCreateHandler := api.NewRunCreateHandler(logger, s.ah)
	runEventsHandler := api.NewRunEventsHandler(logger, s.e, s.ost, s.dm)

	changeGroupsUpdateTokensHandler := api.NewChangeGroupsUpdateTokensHandler(logger, s.readDB)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter()

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

	apirouter.Handle("/runs/events", runEventsHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}", runHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", runActionsHandler).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", runTaskActionsHandler).Methods("PUT")
	apirouter.Handle("/runs", runsHandler).Methods("GET")
	apirouter.Handle("/runs", runCreateHandler).Methods("POST")

	apirouter.Handle("/changegroups", changeGroupsUpdateTokensHandler).Methods("GET")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(router)

	// Return a bad request when it doesn't match any route
	mainrouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	go s.executorTasksCleanerLoop(ctx)
	go s.runsSchedulerLoop(ctx)
	go s.runTasksUpdaterLoop(ctx)
	go s.fetcherLoop(ctx)
	go s.finishedRunsArchiverLoop(ctx)
	go s.compactChangeGroupsLoop(ctx)
	go s.cacheCleanerLoop(ctx, s.c.RunCacheExpireInterval)
	go s.executorTaskUpdateHandler(ctx, ch)

	go s.etcdPingerLoop(ctx)

	var tlsConfig *tls.Config
	if s.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(s.c.Web.TLSCertFile, s.c.Web.TLSKeyFile, "", false)
		if err != nil {
			log.Errorf("err: %+v")
			return err
		}
	}

	httpServer := http.Server{
		Addr:      s.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Infof("runservice scheduler exiting")
		httpServer.Close()
	case err := <-lerrCh:
		if err != nil {
			log.Errorf("http server listen error: %v", err)
			return err
		}
	case err := <-errCh:
		if err != nil {
			log.Errorf("error: %+v", err)
			return err
		}
	}

	return nil
}
