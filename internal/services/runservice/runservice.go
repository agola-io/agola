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

package runservice

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"time"

	scommon "github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/config"
	"github.com/sorintlab/agola/internal/services/runservice/action"
	"github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/services/runservice/common"
	"github.com/sorintlab/agola/internal/services/runservice/readdb"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"

	ghandlers "github.com/gorilla/handlers"
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

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
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
		E:   e,
		OST: ost,
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

	go s.readDB.Run(ctx)

	ch := make(chan *types.ExecutorTask)

	// noop coors handler
	corsHandler := func(h http.Handler) http.Handler {
		return h
	}

	corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
	corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "X-CSRF-Token", "Authorization"})
	corsAllowedOriginsOptions := ghandlers.AllowedOrigins([]string{"*"})
	corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions)

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

	apirouter.Handle("/runs/{runid}", runHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", runActionsHandler).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", runTaskActionsHandler).Methods("PUT")
	apirouter.Handle("/runs", runsHandler).Methods("GET")
	apirouter.Handle("/runs", runCreateHandler).Methods("POST")

	apirouter.Handle("/changegroups", changeGroupsUpdateTokensHandler).Methods("GET")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(corsHandler(router))

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
		return nil
	case err := <-lerrCh:
		log.Errorf("http server listen error: %v", err)
		return err
	case err := <-errCh:
		log.Errorf("error: %+v", err)
		return err
	}
}
