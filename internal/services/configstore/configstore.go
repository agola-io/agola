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

package configstore

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	scommon "agola.io/agola/internal/common"
	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/etcd"
	slog "agola.io/agola/internal/log"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	action "agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/api"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/mvcc/mvccpb"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func (s *Configstore) maintenanceModeWatcherLoop(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) {
	for {
		log.Debugf("maintenanceModeWatcherLoop")

		// at first watch restart from previous processed revision
		if err := s.maintenanceModeWatcher(ctx, runCtxCancel, maintenanceModeEnabled); err != nil {
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

func (s *Configstore) maintenanceModeWatcher(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) error {
	log.Infof("watcher: maintenance mode enabled: %t", maintenanceModeEnabled)
	resp, err := s.e.Get(ctx, common.EtcdMaintenanceKey, 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}

	if len(resp.Kvs) > 0 {
		log.Infof("maintenance mode key is present")
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
			return wresp.Err()
		}

		for _, ev := range wresp.Events {
			switch ev.Type {
			case mvccpb.PUT:
				log.Infof("maintenance mode key set")
				if !maintenanceModeEnabled {
					runCtxCancel()
				}

			case mvccpb.DELETE:
				log.Infof("maintenance mode key removed")
				if maintenanceModeEnabled {
					runCtxCancel()
				}
			}
		}
	}

	return nil
}

type Configstore struct {
	c               *config.Configstore
	e               *etcd.Store
	dm              *datamanager.DataManager
	readDB          *readdb.ReadDB
	ost             *objectstorage.ObjStorage
	ah              *action.ActionHandler
	maintenanceMode bool
}

func NewConfigstore(ctx context.Context, l *zap.Logger, c *config.Configstore) (*Configstore, error) {
	if l != nil {
		logger = l
	}
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}
	log = logger.Sugar()

	ost, err := scommon.NewObjectStorage(&c.ObjectStorage)
	if err != nil {
		return nil, err
	}
	e, err := scommon.NewEtcd(&c.Etcd, logger, "configstore")
	if err != nil {
		return nil, err
	}

	cs := &Configstore{
		c:   c,
		e:   e,
		ost: ost,
	}

	dmConf := &datamanager.DataManagerConfig{
		BasePath: "configdata",
		E:        e,
		OST:      ost,
		DataTypes: []string{
			string(types.ConfigTypeUser),
			string(types.ConfigTypeOrg),
			string(types.ConfigTypeOrgMember),
			string(types.ConfigTypeProjectGroup),
			string(types.ConfigTypeProject),
			string(types.ConfigTypeRemoteSource),
			string(types.ConfigTypeSecret),
			string(types.ConfigTypeVariable),
		},
	}
	dm, err := datamanager.NewDataManager(ctx, logger, dmConf)
	if err != nil {
		return nil, err
	}
	readDB, err := readdb.NewReadDB(ctx, logger, filepath.Join(c.DataDir, "readdb"), e, ost, dm)
	if err != nil {
		return nil, err
	}

	cs.dm = dm
	cs.readDB = readDB

	ah := action.NewActionHandler(logger, readDB, dm, e)
	cs.ah = ah

	return cs, nil
}

func (s *Configstore) setupDefaultRouter() http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(logger, s.ah, s.e)
	exportHandler := api.NewExportHandler(logger, s.ah)

	projectGroupHandler := api.NewProjectGroupHandler(logger, s.ah, s.readDB)
	projectGroupSubgroupsHandler := api.NewProjectGroupSubgroupsHandler(logger, s.ah, s.readDB)
	projectGroupProjectsHandler := api.NewProjectGroupProjectsHandler(logger, s.ah, s.readDB)
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(logger, s.ah, s.readDB)
	updateProjectGroupHandler := api.NewUpdateProjectGroupHandler(logger, s.ah, s.readDB)
	deleteProjectGroupHandler := api.NewDeleteProjectGroupHandler(logger, s.ah)

	projectHandler := api.NewProjectHandler(logger, s.ah, s.readDB)
	createProjectHandler := api.NewCreateProjectHandler(logger, s.ah, s.readDB)
	updateProjectHandler := api.NewUpdateProjectHandler(logger, s.ah, s.readDB)
	deleteProjectHandler := api.NewDeleteProjectHandler(logger, s.ah)

	secretsHandler := api.NewSecretsHandler(logger, s.ah, s.readDB)
	createSecretHandler := api.NewCreateSecretHandler(logger, s.ah)
	updateSecretHandler := api.NewUpdateSecretHandler(logger, s.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(logger, s.ah)

	variablesHandler := api.NewVariablesHandler(logger, s.ah, s.readDB)
	createVariableHandler := api.NewCreateVariableHandler(logger, s.ah)
	updateVariableHandler := api.NewUpdateVariableHandler(logger, s.ah)
	deleteVariableHandler := api.NewDeleteVariableHandler(logger, s.ah)

	userHandler := api.NewUserHandler(logger, s.readDB)
	usersHandler := api.NewUsersHandler(logger, s.readDB)
	createUserHandler := api.NewCreateUserHandler(logger, s.ah)
	updateUserHandler := api.NewUpdateUserHandler(logger, s.ah)
	deleteUserHandler := api.NewDeleteUserHandler(logger, s.ah)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, s.ah)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, s.ah)
	updateUserLAHandler := api.NewUpdateUserLAHandler(logger, s.ah)

	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, s.ah)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(logger, s.ah)

	userOrgsHandler := api.NewUserOrgsHandler(logger, s.ah)

	orgHandler := api.NewOrgHandler(logger, s.readDB)
	orgsHandler := api.NewOrgsHandler(logger, s.readDB)
	createOrgHandler := api.NewCreateOrgHandler(logger, s.ah)
	deleteOrgHandler := api.NewDeleteOrgHandler(logger, s.ah)

	orgMembersHandler := api.NewOrgMembersHandler(logger, s.ah)
	addOrgMemberHandler := api.NewAddOrgMemberHandler(logger, s.ah)
	removeOrgMemberHandler := api.NewRemoveOrgMemberHandler(logger, s.ah)

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, s.readDB)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(logger, s.readDB)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, s.ah)
	updateRemoteSourceHandler := api.NewUpdateRemoteSourceHandler(logger, s.ah)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(logger, s.ah)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/projectgroups/{projectgroupref}", projectGroupHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/subgroups", projectGroupSubgroupsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/projects", projectGroupProjectsHandler).Methods("GET")
	apirouter.Handle("/projectgroups", createProjectGroupHandler).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}", updateProjectGroupHandler).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}", deleteProjectGroupHandler).Methods("DELETE")

	apirouter.Handle("/projects/{projectref}", projectHandler).Methods("GET")
	apirouter.Handle("/projects", createProjectHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}", updateProjectHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}", deleteProjectHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", createSecretHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}/secrets", createSecretHandler).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", updateSecretHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", updateSecretHandler).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables", createVariableHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}/variables", createVariableHandler).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", updateVariableHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", updateVariableHandler).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", deleteVariableHandler).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", deleteVariableHandler).Methods("DELETE")

	apirouter.Handle("/users/{userref}", userHandler).Methods("GET")
	apirouter.Handle("/users", usersHandler).Methods("GET")
	apirouter.Handle("/users", createUserHandler).Methods("POST")
	apirouter.Handle("/users/{userref}", updateUserHandler).Methods("PUT")
	apirouter.Handle("/users/{userref}", deleteUserHandler).Methods("DELETE")

	apirouter.Handle("/users/{userref}/linkedaccounts", createUserLAHandler).Methods("POST")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", deleteUserLAHandler).Methods("DELETE")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", updateUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{userref}/tokens", createUserTokenHandler).Methods("POST")
	apirouter.Handle("/users/{userref}/tokens/{tokenname}", deleteUserTokenHandler).Methods("DELETE")

	apirouter.Handle("/users/{userref}/orgs", userOrgsHandler).Methods("GET")

	apirouter.Handle("/orgs/{orgref}", orgHandler).Methods("GET")
	apirouter.Handle("/orgs", orgsHandler).Methods("GET")
	apirouter.Handle("/orgs", createOrgHandler).Methods("POST")
	apirouter.Handle("/orgs/{orgref}", deleteOrgHandler).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/members", orgMembersHandler).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", addOrgMemberHandler).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", removeOrgMemberHandler).Methods("DELETE")

	apirouter.Handle("/remotesources/{remotesourceref}", remoteSourceHandler).Methods("GET")
	apirouter.Handle("/remotesources", remoteSourcesHandler).Methods("GET")
	apirouter.Handle("/remotesources", createRemoteSourceHandler).Methods("POST")
	apirouter.Handle("/remotesources/{remotesourceref}", updateRemoteSourceHandler).Methods("PUT")
	apirouter.Handle("/remotesources/{remotesourceref}", deleteRemoteSourceHandler).Methods("DELETE")

	apirouter.Handle("/maintenance", maintenanceModeHandler).Methods("PUT", "DELETE")

	apirouter.Handle("/export", exportHandler).Methods("GET")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(router)

	return mainrouter
}

func (s *Configstore) setupMaintenanceRouter() http.Handler {
	maintenanceModeHandler := api.NewMaintenanceModeHandler(logger, s.ah, s.e)
	exportHandler := api.NewExportHandler(logger, s.ah)
	importHandler := api.NewImportHandler(logger, s.ah)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/maintenance", maintenanceModeHandler).Methods("PUT", "DELETE")

	apirouter.Handle("/export", exportHandler).Methods("GET")
	apirouter.Handle("/import", importHandler).Methods("POST")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(router)

	return mainrouter
}

func (s *Configstore) Run(ctx context.Context) error {
	for {
		if err := s.run(ctx); err != nil {
			log.Errorf("run error: %+v", err)
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			log.Infof("configstore exiting")
			return nil
		case <-sleepCh:
		}
	}
}

func (s *Configstore) run(ctx context.Context) error {
	var tlsConfig *tls.Config
	if s.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(s.c.Web.TLSCertFile, s.c.Web.TLSKeyFile, "", false)
		if err != nil {
			log.Errorf("err: %+v")
			return err
		}
	}

	resp, err := s.e.Get(ctx, common.EtcdMaintenanceKey, 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}

	maintenanceMode := false
	if len(resp.Kvs) > 0 {
		log.Infof("maintenance mode key is present")
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
		mainrouter = s.setupDefaultRouter()

		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

		// TODO(sgotti) wait for all goroutines exiting
		util.GoWait(&wg, func() { errCh <- s.dm.Run(ctx, dmReadyCh) })

		// wait for dm to be ready
		<-dmReadyCh

		util.GoWait(&wg, func() { errCh <- s.readDB.Run(ctx) })
	}

	httpServer := http.Server{
		Addr:      s.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error, 1)
	util.GoWait(&wg, func() {
		lerrCh <- httpServer.ListenAndServe()
	})
	defer httpServer.Close()

	select {
	case <-ctx.Done():
		log.Infof("configstore run exiting")
	case err := <-lerrCh:
		if err != nil {
			log.Errorf("http server listen error: %+v", err)
			return err
		}
	case err := <-errCh:
		if err != nil {
			log.Errorf("error: %+v", err)
			return err
		}
	}

	cancel()
	httpServer.Close()
	wg.Wait()

	return err
}
