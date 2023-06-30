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
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"

	scommon "agola.io/agola/internal/common"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	action "agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/api"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/services/handlers"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
)

func (s *Configstore) maintenanceModeWatcherLoop(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) {
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

func (s *Configstore) maintenanceModeWatcher(ctx context.Context, runCtxCancel context.CancelFunc, maintenanceModeEnabled bool) error {
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

type Configstore struct {
	log             zerolog.Logger
	c               *config.Configstore
	ost             *objectstorage.ObjStorage
	d               *db.DB
	lf              lock.LockFactory
	ah              *action.ActionHandler
	maintenanceMode bool
}

func NewConfigstore(ctx context.Context, log zerolog.Logger, c *config.Configstore) (*Configstore, error) {
	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
	}

	ost, err := scommon.NewObjectStorage(&c.ObjectStorage)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cs := &Configstore{
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
	cs.d = d

	var lf lock.LockFactory
	switch c.DB.Type {
	case sql.Sqlite3:
		ll := lock.NewLocalLocks()
		lf = lock.NewLocalLockFactory(ll)
	case sql.Postgres:
		lf = lock.NewPGLockFactory(sdb)
	default:
		return nil, errors.Errorf("unknown db type %q", c.DB.Type)
	}
	cs.lf = lf

	dbm := manager.NewDBManager(log, d, lf)

	if err := common.SetupDB(ctx, dbm); err != nil {
		return nil, errors.Wrap(err, "failed to setup db")
	}

	ah := action.NewActionHandler(log, d, lf)
	cs.ah = ah

	return cs, nil
}

func (s *Configstore) setupDefaultRouter() http.Handler {
	maintenanceStatusHandler := api.NewMaintenanceStatusHandler(s.log, s.ah, false)
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah)
	exportHandler := api.NewExportHandler(s.log, s.ah)
	importHandler := api.NewImportHandler(s.log, s.ah)

	projectGroupHandler := api.NewProjectGroupHandler(s.log, s.ah, s.d)
	projectGroupSubgroupsHandler := api.NewProjectGroupSubgroupsHandler(s.log, s.ah, s.d)
	projectGroupProjectsHandler := api.NewProjectGroupProjectsHandler(s.log, s.ah, s.d)
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(s.log, s.ah, s.d)
	updateProjectGroupHandler := api.NewUpdateProjectGroupHandler(s.log, s.ah, s.d)
	deleteProjectGroupHandler := api.NewDeleteProjectGroupHandler(s.log, s.ah)

	projectHandler := api.NewProjectHandler(s.log, s.ah, s.d)
	createProjectHandler := api.NewCreateProjectHandler(s.log, s.ah, s.d)
	updateProjectHandler := api.NewUpdateProjectHandler(s.log, s.ah, s.d)
	deleteProjectHandler := api.NewDeleteProjectHandler(s.log, s.ah)

	secretsHandler := api.NewSecretsHandler(s.log, s.ah, s.d)
	createSecretHandler := api.NewCreateSecretHandler(s.log, s.ah)
	updateSecretHandler := api.NewUpdateSecretHandler(s.log, s.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(s.log, s.ah)

	variablesHandler := api.NewVariablesHandler(s.log, s.ah, s.d)
	createVariableHandler := api.NewCreateVariableHandler(s.log, s.ah)
	updateVariableHandler := api.NewUpdateVariableHandler(s.log, s.ah)
	deleteVariableHandler := api.NewDeleteVariableHandler(s.log, s.ah)

	userHandler := api.NewUserHandler(s.log, s.d)
	usersHandler := api.NewUsersHandler(s.log, s.d)
	createUserHandler := api.NewCreateUserHandler(s.log, s.ah)
	updateUserHandler := api.NewUpdateUserHandler(s.log, s.ah)
	deleteUserHandler := api.NewDeleteUserHandler(s.log, s.ah)
	userOrgInvitationsHandler := api.NewUserOrgInvitationsHandler(s.log, s.ah)
	userOrgInvitationActionHandler := api.NewOrgInvitationActionHandler(s.log, s.ah)

	userLinkedAccountsHandler := api.NewUserLinkedAccountsHandler(s.log, s.ah)
	createUserLAHandler := api.NewCreateUserLAHandler(s.log, s.ah)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(s.log, s.ah)
	updateUserLAHandler := api.NewUpdateUserLAHandler(s.log, s.ah)

	userTokensHandler := api.NewUserTokensHandler(s.log, s.ah)
	createUserTokenHandler := api.NewCreateUserTokenHandler(s.log, s.ah)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(s.log, s.ah)

	userOrgsHandler := api.NewUserOrgsHandler(s.log, s.ah)

	orgHandler := api.NewOrgHandler(s.log, s.d)
	orgsHandler := api.NewOrgsHandler(s.log, s.d)
	createOrgHandler := api.NewCreateOrgHandler(s.log, s.ah)
	updateOrgHandler := api.NewUpdateOrgHandler(s.log, s.ah)
	deleteOrgHandler := api.NewDeleteOrgHandler(s.log, s.ah)
	orgInvitationsHandler := api.NewOrgInvitationsHandler(s.log, s.ah)

	orgMembersHandler := api.NewOrgMembersHandler(s.log, s.ah)
	addOrgMemberHandler := api.NewAddOrgMemberHandler(s.log, s.ah)
	removeOrgMemberHandler := api.NewRemoveOrgMemberHandler(s.log, s.ah)

	remoteSourceHandler := api.NewRemoteSourceHandler(s.log, s.d)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(s.log, s.d)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(s.log, s.ah)
	updateRemoteSourceHandler := api.NewUpdateRemoteSourceHandler(s.log, s.ah)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(s.log, s.ah)

	linkedAccountsHandler := api.NewLinkedAccountsHandler(s.log, s.d)

	createOrgInvitationHandler := api.NewCreateOrgInvitationHandler(s.log, s.ah)
	deleteOrgInvitationHandler := api.NewDeleteOrgInvitationHandler(s.log, s.ah)
	orgInvitationHandler := api.NewOrgInvitationHandler(s.log, s.ah)

	authHandler := handlers.NewInternalAuthChecker(s.log, s.c.APIToken)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Use(authHandler)

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
	apirouter.Handle("/users/{userref}/org_invitations", userOrgInvitationsHandler).Methods("GET")

	apirouter.Handle("/users/{userref}/linkedaccounts", userLinkedAccountsHandler).Methods("GET")
	apirouter.Handle("/users/{userref}/linkedaccounts", createUserLAHandler).Methods("POST")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", deleteUserLAHandler).Methods("DELETE")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", updateUserLAHandler).Methods("PUT")
	apirouter.Handle("/users/{userref}/tokens", userTokensHandler).Methods("GET")
	apirouter.Handle("/users/{userref}/tokens", createUserTokenHandler).Methods("POST")
	apirouter.Handle("/users/{userref}/tokens/{tokenname}", deleteUserTokenHandler).Methods("DELETE")

	apirouter.Handle("/users/{userref}/orgs", userOrgsHandler).Methods("GET")

	apirouter.Handle("/orgs/{orgref}", orgHandler).Methods("GET")
	apirouter.Handle("/orgs", orgsHandler).Methods("GET")
	apirouter.Handle("/orgs", createOrgHandler).Methods("POST")
	apirouter.Handle("/orgs/{orgref}", updateOrgHandler).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}", deleteOrgHandler).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/members", orgMembersHandler).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", addOrgMemberHandler).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", removeOrgMemberHandler).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/invitations", orgInvitationsHandler).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/invitations", createOrgInvitationHandler).Methods("POST")
	apirouter.Handle("/orgs/{orgref}/invitations/{userref}", orgInvitationHandler).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/invitations/{userref}", deleteOrgInvitationHandler).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/invitations/{userref}/actions", userOrgInvitationActionHandler).Methods("PUT")

	apirouter.Handle("/remotesources/{remotesourceref}", remoteSourceHandler).Methods("GET")
	apirouter.Handle("/remotesources", remoteSourcesHandler).Methods("GET")
	apirouter.Handle("/remotesources", createRemoteSourceHandler).Methods("POST")
	apirouter.Handle("/remotesources/{remotesourceref}", updateRemoteSourceHandler).Methods("PUT")
	apirouter.Handle("/remotesources/{remotesourceref}", deleteRemoteSourceHandler).Methods("DELETE")

	apirouter.Handle("/linkedaccounts", linkedAccountsHandler).Methods("GET")

	apirouter.Handle("/maintenance", maintenanceStatusHandler).Methods("GET")
	apirouter.Handle("/maintenance", maintenanceModeHandler).Methods("PUT", "DELETE")

	apirouter.Handle("/export", exportHandler).Methods("GET")
	apirouter.Handle("/import", importHandler).Methods("POST")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(router)

	return mainrouter
}

func (s *Configstore) setupMaintenanceRouter() http.Handler {
	maintenanceStatusHandler := api.NewMaintenanceStatusHandler(s.log, s.ah, true)
	maintenanceModeHandler := api.NewMaintenanceModeHandler(s.log, s.ah)
	exportHandler := api.NewExportHandler(s.log, s.ah)
	importHandler := api.NewImportHandler(s.log, s.ah)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	apirouter.Handle("/maintenance", maintenanceStatusHandler).Methods("GET")
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
			log.Err(err).Msgf("run error")
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			s.log.Info().Msgf("configstore exiting")
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
	// dmReadyCh := make(chan struct{})

	var mainrouter http.Handler
	if s.maintenanceMode {
		mainrouter = s.setupMaintenanceRouter()
		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

	} else {
		mainrouter = s.setupDefaultRouter()

		util.GoWait(&wg, func() { s.maintenanceModeWatcherLoop(ctx, cancel, s.maintenanceMode) })

		// TODO(sgotti) wait for all goroutines exiting
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
	defer httpServer.Close()

	select {
	case <-ctx.Done():
		log.Info().Msgf("configstore run exiting")
	case err = <-lerrCh:
		if err != nil {
			log.Err(err).Msgf("http server listen error")
		}
	case err = <-errCh:
		if err != nil {
			s.log.Err(err).Send()
		}
	}

	cancel()
	httpServer.Close()
	wg.Wait()

	return nil
}
