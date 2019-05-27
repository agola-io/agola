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

package gateway

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	scommon "github.com/sorintlab/agola/internal/common"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/common"
	"github.com/sorintlab/agola/internal/services/config"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/gateway/handlers"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/util"

	jwt "github.com/dgrijalva/jwt-go"
	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

const (
	maxRequestSize = 1024 * 1024
)

type Gateway struct {
	c *config.Gateway

	ost               *objectstorage.ObjStorage
	runserviceClient  *rsapi.Client
	configstoreClient *csapi.Client
	ah                *action.ActionHandler
	sd                *common.TokenSigningData
}

func NewGateway(gc *config.Config) (*Gateway, error) {
	c := &gc.Gateway
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	if c.Web.ListenAddress == "" {
		return nil, errors.Errorf("listen address undefined")
	}

	if c.Web.TLS {
		if c.Web.TLSKeyFile == "" {
			return nil, errors.Errorf("no tls key file specified")
		}
		if c.Web.TLSCertFile == "" {
			return nil, errors.Errorf("no tls cert file specified")
		}
	}

	sd := &common.TokenSigningData{Duration: c.TokenSigning.Duration}
	switch c.TokenSigning.Method {
	case "hmac":
		sd.Method = jwt.SigningMethodHS256
		if c.TokenSigning.Key == "" {
			return nil, errors.Errorf("empty token signing key for hmac method")
		}
		sd.Key = []byte(c.TokenSigning.Key)
	case "rsa":
		if c.TokenSigning.PrivateKeyPath == "" {
			return nil, errors.Errorf("token signing private key file for rsa method not defined")
		}
		if c.TokenSigning.PublicKeyPath == "" {
			return nil, errors.Errorf("token signing public key file for rsa method not defined")
		}

		sd.Method = jwt.SigningMethodRS256
		privateKeyData, err := ioutil.ReadFile(c.TokenSigning.PrivateKeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading token signing private key")
		}
		sd.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing token signing private key")
		}
		publicKeyData, err := ioutil.ReadFile(c.TokenSigning.PublicKeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading token signing public key")
		}
		sd.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing token signing public key")
		}
	case "":
		return nil, errors.Errorf("missing token signing method")
	default:
		return nil, errors.Errorf("unknown token signing method: %q", c.TokenSigning.Method)
	}

	ost, err := scommon.NewObjectStorage(&c.ObjectStorage)
	if err != nil {
		return nil, err
	}

	configstoreClient := csapi.NewClient(c.ConfigstoreURL)
	runserviceClient := rsapi.NewClient(c.RunserviceURL)

	ah := action.NewActionHandler(logger, sd, configstoreClient, runserviceClient, gc.ID, c.APIExposedURL, c.WebExposedURL)

	return &Gateway{
		c:                 c,
		ost:               ost,
		runserviceClient:  runserviceClient,
		configstoreClient: configstoreClient,
		ah:                ah,
		sd:                sd,
	}, nil
}

func (g *Gateway) Run(ctx context.Context) error {
	// noop coors handler
	corsHandler := func(h http.Handler) http.Handler {
		return h
	}

	corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
	corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "X-CSRF-Token", "Authorization"})
	corsAllowedOriginsOptions := ghandlers.AllowedOrigins([]string{"*"})
	corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions)

	webhooksHandler := &webhooksHandler{log: log, ah: g.ah, configstoreClient: g.configstoreClient, runserviceClient: g.runserviceClient, apiExposedURL: g.c.APIExposedURL}

	projectGroupHandler := api.NewProjectGroupHandler(logger, g.ah)
	projectGroupSubgroupsHandler := api.NewProjectGroupSubgroupsHandler(logger, g.ah)
	projectGroupProjectsHandler := api.NewProjectGroupProjectsHandler(logger, g.ah)
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(logger, g.ah)
	updateProjectGroupHandler := api.NewUpdateProjectGroupHandler(logger, g.ah)
	deleteProjectGroupHandler := api.NewDeleteProjectGroupHandler(logger, g.ah)

	projectHandler := api.NewProjectHandler(logger, g.ah)
	createProjectHandler := api.NewCreateProjectHandler(logger, g.ah)
	updateProjectHandler := api.NewUpdateProjectHandler(logger, g.ah)
	deleteProjectHandler := api.NewDeleteProjectHandler(logger, g.ah)
	projectReconfigHandler := api.NewProjectReconfigHandler(logger, g.ah)
	projectUpdateRepoLinkedAccountHandler := api.NewProjectUpdateRepoLinkedAccountHandler(logger, g.ah)

	secretHandler := api.NewSecretHandler(logger, g.ah)
	createSecretHandler := api.NewCreateSecretHandler(logger, g.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(logger, g.ah)

	variableHandler := api.NewVariableHandler(logger, g.ah)
	createVariableHandler := api.NewCreateVariableHandler(logger, g.ah)
	deleteVariableHandler := api.NewDeleteVariableHandler(logger, g.ah)

	currentUserHandler := api.NewCurrentUserHandler(logger, g.ah)
	userHandler := api.NewUserHandler(logger, g.ah)
	usersHandler := api.NewUsersHandler(logger, g.ah)
	createUserHandler := api.NewCreateUserHandler(logger, g.ah)
	deleteUserHandler := api.NewDeleteUserHandler(logger, g.ah)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, g.ah)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, g.ah)
	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, g.ah)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(logger, g.ah)

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, g.ah)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, g.ah)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(logger, g.ah)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(logger, g.ah)

	orgHandler := api.NewOrgHandler(logger, g.ah)
	orgsHandler := api.NewOrgsHandler(logger, g.ah)
	createOrgHandler := api.NewCreateOrgHandler(logger, g.ah)
	deleteOrgHandler := api.NewDeleteOrgHandler(logger, g.ah)

	orgMembersHandler := api.NewOrgMembersHandler(logger, g.ah)
	addOrgMemberHandler := api.NewAddOrgMemberHandler(logger, g.ah)
	removeOrgMemberHandler := api.NewRemoveOrgMemberHandler(logger, g.ah)

	runHandler := api.NewRunHandler(logger, g.ah)
	runsHandler := api.NewRunsHandler(logger, g.ah)
	runtaskHandler := api.NewRuntaskHandler(logger, g.ah)
	runActionsHandler := api.NewRunActionsHandler(logger, g.ah)
	runTaskActionsHandler := api.NewRunTaskActionsHandler(logger, g.ah)

	logsHandler := api.NewLogsHandler(logger, g.ah)

	userRemoteReposHandler := api.NewUserRemoteReposHandler(logger, g.ah, g.configstoreClient)

	badgeHandler := api.NewBadgeHandler(logger, g.ah)

	reposHandler := api.NewReposHandler(logger, g.c.GitserverURL)

	loginUserHandler := api.NewLoginUserHandler(logger, g.ah)
	authorizeHandler := api.NewAuthorizeHandler(logger, g.ah)
	registerHandler := api.NewRegisterUserHandler(logger, g.ah)
	oauth2callbackHandler := api.NewOAuth2CallbackHandler(logger, g.ah)

	router := mux.NewRouter()

	apirouter := mux.NewRouter().PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	authForcedHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, true)
	authOptionalHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, false)

	router.PathPrefix("/api/v1alpha").Handler(apirouter)

	apirouter.Handle("/logs", authOptionalHandler(logsHandler)).Methods("GET")

	//apirouter.Handle("/projectgroups", authForcedHandler(projectsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(projectGroupHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/subgroups", authForcedHandler(projectGroupSubgroupsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/projects", authForcedHandler(projectGroupProjectsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups", authForcedHandler(createProjectGroupHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(updateProjectGroupHandler)).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(deleteProjectGroupHandler)).Methods("DELETE")

	apirouter.Handle("/projects/{projectref}", authForcedHandler(projectHandler)).Methods("GET")
	apirouter.Handle("/projects", authForcedHandler(createProjectHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}", authForcedHandler(updateProjectHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}", authForcedHandler(deleteProjectHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/reconfig", authForcedHandler(projectReconfigHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/updaterepolinkedaccount", authForcedHandler(projectUpdateRepoLinkedAccountHandler)).Methods("PUT")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(secretHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(secretHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", authForcedHandler(variableHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", authForcedHandler(variableHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables", authForcedHandler(createVariableHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/variables", authForcedHandler(createVariableHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", authForcedHandler(deleteVariableHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", authForcedHandler(deleteVariableHandler)).Methods("DELETE")

	apirouter.Handle("/user", authForcedHandler(currentUserHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}", authForcedHandler(userHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(usersHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(createUserHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}", authForcedHandler(deleteUserHandler)).Methods("DELETE")

	apirouter.Handle("/users/{userref}/linkedaccounts", authForcedHandler(createUserLAHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", authForcedHandler(deleteUserLAHandler)).Methods("DELETE")
	apirouter.Handle("/users/{userref}/tokens", authForcedHandler(createUserTokenHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/tokens/{tokenname}", authForcedHandler(deleteUserTokenHandler)).Methods("DELETE")

	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(remoteSourceHandler)).Methods("GET")
	apirouter.Handle("/remotesources", authForcedHandler(createRemoteSourceHandler)).Methods("POST")
	apirouter.Handle("/remotesources", authOptionalHandler(remoteSourcesHandler)).Methods("GET")
	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(deleteRemoteSourceHandler)).Methods("DELETE")

	apirouter.Handle("/orgs/{orgref}", authForcedHandler(orgHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(orgsHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(createOrgHandler)).Methods("POST")
	apirouter.Handle("/orgs/{orgref}", authForcedHandler(deleteOrgHandler)).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/members", authForcedHandler(orgMembersHandler)).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(addOrgMemberHandler)).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(removeOrgMemberHandler)).Methods("DELETE")

	apirouter.Handle("/runs/{runid}", authForcedHandler(runHandler)).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", authForcedHandler(runActionsHandler)).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}", authForcedHandler(runtaskHandler)).Methods("GET")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", authForcedHandler(runTaskActionsHandler)).Methods("PUT")
	apirouter.Handle("/runs", authForcedHandler(runsHandler)).Methods("GET")

	apirouter.Handle("/user/remoterepos/{remotesourceref}", authForcedHandler(userRemoteReposHandler)).Methods("GET")

	apirouter.Handle("/badges/{projectref}", badgeHandler).Methods("GET")

	// TODO(sgotti) add auth to these requests
	router.Handle("/repos/{rest:.*}", reposHandler).Methods("GET", "POST")

	router.Handle("/api/login", loginUserHandler).Methods("POST")
	router.Handle("/api/authorize", authorizeHandler).Methods("POST")
	router.Handle("/api/register", registerHandler).Methods("POST")
	router.Handle("/api/oauth2/callback", oauth2callbackHandler).Methods("GET")

	router.Handle("/webhooks", webhooksHandler).Methods("POST")
	router.PathPrefix("/").HandlerFunc(handlers.NewWebBundleHandlerFunc(g.c.APIExposedURL))

	maxBytesHandler := handlers.NewMaxBytesHandler(router, 1024*1024)

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(corsHandler(maxBytesHandler))

	var tlsConfig *tls.Config
	if g.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(g.c.Web.TLSCertFile, g.c.Web.TLSKeyFile, "", false)
		if err != nil {
			log.Errorf("err: %+v")
			return err
		}
	}

	httpServer := http.Server{
		Addr:      g.c.Web.ListenAddress,
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
		log.Errorf("http server listen error: %v", err)
		return err
	}
}
