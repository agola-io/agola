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
	"github.com/sorintlab/agola/internal/etcd"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/config"
	"github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/common"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

type ConfigStore struct {
	c             *config.ConfigStore
	e             *etcd.Store
	wal           *wal.WalManager
	readDB        *readdb.ReadDB
	lts           *objectstorage.ObjStorage
	ch            *command.CommandHandler
	listenAddress string
}

func NewConfigStore(ctx context.Context, c *config.ConfigStore) (*ConfigStore, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	lts, err := scommon.NewLTS(&c.LTS)
	if err != nil {
		return nil, err
	}
	e, err := scommon.NewEtcd(&c.Etcd, logger, "configstore")
	if err != nil {
		return nil, err
	}

	cs := &ConfigStore{
		c:   c,
		e:   e,
		lts: lts,
	}

	walConf := &wal.WalManagerConfig{
		E:              e,
		Lts:            lts,
		DataToPathFunc: common.DataToPathFunc,
	}
	wal, err := wal.NewWalManager(ctx, logger, walConf)
	if err != nil {
		return nil, err
	}
	readDB, err := readdb.NewReadDB(ctx, logger, filepath.Join(c.DataDir, "readdb"), e, lts, wal)
	if err != nil {
		return nil, err
	}

	cs.wal = wal
	cs.readDB = readDB

	ch := command.NewCommandHandler(logger, readDB, wal)
	cs.ch = ch

	return cs, nil
}

func (s *ConfigStore) Run(ctx context.Context) error {
	errCh := make(chan error)
	walReadyCh := make(chan struct{})

	go func() { errCh <- s.wal.Run(ctx, walReadyCh) }()

	// wait for wal to be ready
	<-walReadyCh

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
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(logger, s.ch)

	projectHandler := api.NewProjectHandler(logger, s.readDB)
	createProjectHandler := api.NewCreateProjectHandler(logger, s.ch)
	deleteProjectHandler := api.NewDeleteProjectHandler(logger, s.ch)

	secretsHandler := api.NewSecretsHandler(logger, s.readDB)
	createSecretHandler := api.NewCreateSecretHandler(logger, s.ch)
	deleteSecretHandler := api.NewDeleteSecretHandler(logger, s.ch)

	variablesHandler := api.NewVariablesHandler(logger, s.readDB)
	createVariableHandler := api.NewCreateVariableHandler(logger, s.ch)
	deleteVariableHandler := api.NewDeleteVariableHandler(logger, s.ch)

	userHandler := api.NewUserHandler(logger, s.readDB)
	usersHandler := api.NewUsersHandler(logger, s.readDB)
	userByNameHandler := api.NewUserByNameHandler(logger, s.readDB)
	createUserHandler := api.NewCreateUserHandler(logger, s.ch)
	deleteUserHandler := api.NewDeleteUserHandler(logger, s.ch)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, s.ch)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, s.ch)
	updateUserLAHandler := api.NewUpdateUserLAHandler(logger, s.ch)

	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, s.ch)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(logger, s.ch)

	orgHandler := api.NewOrgHandler(logger, s.readDB)
	orgsHandler := api.NewOrgsHandler(logger, s.readDB)
	orgByNameHandler := api.NewOrgByNameHandler(logger, s.readDB)
	createOrgHandler := api.NewCreateOrgHandler(logger, s.ch)
	deleteOrgHandler := api.NewDeleteOrgHandler(logger, s.ch)

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, s.readDB)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(logger, s.readDB)
	remoteSourceByNameHandler := api.NewRemoteSourceByNameHandler(logger, s.readDB)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, s.ch)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(logger, s.ch)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/projectgroups/{projectgroupref}", projectGroupHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/subgroups", projectGroupSubgroupsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/projects", projectGroupProjectsHandler).Methods("GET")
	apirouter.Handle("/projectgroups", createProjectGroupHandler).Methods("PUT")

	apirouter.Handle("/projects/{projectref}", projectHandler).Methods("GET")
	apirouter.Handle("/projects", createProjectHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}", deleteProjectHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", secretsHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", createSecretHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/secrets", createSecretHandler).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", deleteSecretHandler).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", variablesHandler).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables", createVariableHandler).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/variables", createVariableHandler).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", deleteVariableHandler).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", deleteVariableHandler).Methods("DELETE")

	apirouter.Handle("/user/{userid}", userHandler).Methods("GET")
	apirouter.Handle("/users", usersHandler).Methods("GET")
	apirouter.Handle("/users", createUserHandler).Methods("PUT")
	apirouter.Handle("/users/{username}", userByNameHandler).Methods("GET")
	apirouter.Handle("/users/{username}", deleteUserHandler).Methods("DELETE")

	apirouter.Handle("/users/{username}/linkedaccounts", createUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{username}/linkedaccounts/{laid}", deleteUserLAHandler).Methods("DELETE")
	apirouter.Handle("/users/{username}/linkedaccounts/{laid}", updateUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{username}/tokens", createUserTokenHandler).Methods("PUT")
	apirouter.Handle("/users/{username}/tokens/{tokenname}", deleteUserTokenHandler).Methods("DELETE")

	apirouter.Handle("/org/{orgid}", orgHandler).Methods("GET")
	apirouter.Handle("/orgs", orgsHandler).Methods("GET")
	apirouter.Handle("/orgs", createOrgHandler).Methods("PUT")
	apirouter.Handle("/orgs/{orgname}", orgByNameHandler).Methods("GET")
	apirouter.Handle("/orgs/{orgname}", deleteOrgHandler).Methods("DELETE")

	apirouter.Handle("/remotesource/{id}", remoteSourceHandler).Methods("GET")
	apirouter.Handle("/remotesources", remoteSourcesHandler).Methods("GET")
	apirouter.Handle("/remotesources", createRemoteSourceHandler).Methods("PUT")
	apirouter.Handle("/remotesources/{name}", remoteSourceByNameHandler).Methods("GET")
	apirouter.Handle("/remotesources/{name}", deleteRemoteSourceHandler).Methods("DELETE")

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
