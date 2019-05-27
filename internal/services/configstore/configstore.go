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
		E:   e,
		Lts: lts,
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

	go func() { errCh <- s.wal.Run(ctx) }()
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

	userHandler := api.NewUserHandler(logger, s.readDB)
	usersHandler := api.NewUsersHandler(logger, s.readDB)
	userByNameHandler := api.NewUserByNameHandler(logger, s.readDB)
	createUserHandler := api.NewCreateUserHandler(logger, s.ch)
	deleteUserHandler := api.NewDeleteUserHandler(logger, s.ch)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, s.ch)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, s.ch)
	updateUserLAHandler := api.NewUpdateUserLAHandler(logger, s.ch)

	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, s.ch)

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
	apirouter.Handle("/projects/{projectid}", deleteProjectHandler).Methods("DELETE")

	apirouter.Handle("/user/{userid}", userHandler).Methods("GET")
	apirouter.Handle("/users", usersHandler).Methods("GET")
	apirouter.Handle("/users", createUserHandler).Methods("PUT")
	apirouter.Handle("/users/{username}", userByNameHandler).Methods("GET")
	apirouter.Handle("/users/{username}", deleteUserHandler).Methods("DELETE")

	apirouter.Handle("/users/{username}/linkedaccounts", createUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{username}/linkedaccounts/{laid}", deleteUserLAHandler).Methods("DELETE")
	apirouter.Handle("/users/{username}/linkedaccounts/{laid}", updateUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{username}/tokens", createUserTokenHandler).Methods("PUT")

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
