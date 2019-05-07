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

	scommon "github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/etcd"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/config"
	action "github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

type Configstore struct {
	c             *config.Configstore
	e             *etcd.Store
	dm            *datamanager.DataManager
	readDB        *readdb.ReadDB
	ost           *objectstorage.ObjStorage
	ah            *action.ActionHandler
	listenAddress string
}

func NewConfigstore(ctx context.Context, c *config.Configstore) (*Configstore, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

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
		E:   e,
		OST: ost,
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

	ah := action.NewActionHandler(logger, readDB, dm)
	cs.ah = ah

	return cs, nil
}

func (s *Configstore) Run(ctx context.Context) error {
	errCh := make(chan error)
	dmReadyCh := make(chan struct{})

	go func() { errCh <- s.dm.Run(ctx, dmReadyCh) }()

	// wait for dm to be ready
	<-dmReadyCh

	go func() { errCh <- s.readDB.Run(ctx) }()

	// noop coors handler
	corsHandler := func(h http.Handler) http.Handler {
		return h
	}

	corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
	corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "X-CSRF-Token", "Authorization"})
	corsAllowedOriginsOptions := ghandlers.AllowedOrigins([]string{"*"})
	corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions)

	projectGroupHandler := api.NewProjectGroupHandler(logger, s.readDB)
	projectGroupSubgroupsHandler := api.NewProjectGroupSubgroupsHandler(logger, s.readDB)
	projectGroupProjectsHandler := api.NewProjectGroupProjectsHandler(logger, s.readDB)
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(logger, s.ah, s.readDB)

	projectHandler := api.NewProjectHandler(logger, s.readDB)
	createProjectHandler := api.NewCreateProjectHandler(logger, s.ah, s.readDB)
	deleteProjectHandler := api.NewDeleteProjectHandler(logger, s.ah)

	secretsHandler := api.NewSecretsHandler(logger, s.readDB)
	createSecretHandler := api.NewCreateSecretHandler(logger, s.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(logger, s.ah)

	variablesHandler := api.NewVariablesHandler(logger, s.readDB)
	createVariableHandler := api.NewCreateVariableHandler(logger, s.ah)
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

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, s.readDB)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(logger, s.readDB)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, s.ah)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(logger, s.ah)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/projectgroups/{projectgroupref}", projectGroupHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/subgroups", projectGroupSubgroupsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/projects", projectGroupProjectsHandler).Methods("GET")
	apirouter.Handle("/projectgroups", createProjectGroupHandler).Methods("POST")

	apirouter.Handle("/projects/{projectref}", projectHandler).Methods("GET")
	apirouter.Handle("/projects", createProjectHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}", deleteProjectHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", createSecretHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}/secrets", createSecretHandler).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables", createVariableHandler).Methods("POST")
	apirouter.Handle("/projects/{projectref}/variables", createVariableHandler).Methods("POST")
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

	apirouter.Handle("/remotesources/{remotesourceref}", remoteSourceHandler).Methods("GET")
	apirouter.Handle("/remotesources", remoteSourcesHandler).Methods("GET")
	apirouter.Handle("/remotesources", createRemoteSourceHandler).Methods("POST")
	apirouter.Handle("/remotesources/{remotesourceref}", deleteRemoteSourceHandler).Methods("DELETE")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(corsHandler(router))

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
		log.Infof("configstore exiting")
		httpServer.Close()
		return nil
	case err := <-lerrCh:
		log.Errorf("http server listen error: %+v", err)
		return err
	case err := <-errCh:
		log.Errorf("error: %+v", err)
		return err
	}
}
