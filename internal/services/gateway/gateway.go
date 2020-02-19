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

package gateway

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	scommon "agola.io/agola/internal/common"
	slog "agola.io/agola/internal/log"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/gateway/api"
	"agola.io/agola/internal/services/gateway/handlers"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	rsclient "agola.io/agola/services/runservice/client"

	jwt "github.com/dgrijalva/jwt-go"
	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
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
	runserviceClient  *rsclient.Client
	configstoreClient *csclient.Client
	ah                *action.ActionHandler
	sd                *common.TokenSigningData
}

func NewGateway(ctx context.Context, l *zap.Logger, gc *config.Config) (*Gateway, error) {
	c := &gc.Gateway

	if l != nil {
		logger = l
	}
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}
	log = logger.Sugar()

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
			return nil, errors.Errorf("error reading token signing private key: %w", err)
		}
		sd.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
		if err != nil {
			return nil, errors.Errorf("error parsing token signing private key: %w", err)
		}
		publicKeyData, err := ioutil.ReadFile(c.TokenSigning.PublicKeyPath)
		if err != nil {
			return nil, errors.Errorf("error reading token signing public key: %w", err)
		}
		sd.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
		if err != nil {
			return nil, errors.Errorf("error parsing token signing public key: %w", err)
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

	configstoreClient := csclient.NewClient(c.ConfigstoreURL)
	runserviceClient := rsclient.NewClient(c.RunserviceURL)

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

	if len(g.c.Web.AllowedOrigins) > 0 {
		corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
		corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "X-CSRF-Token", "Authorization"})
		corsAllowedOriginsOptions := ghandlers.AllowedOrigins(g.c.Web.AllowedOrigins)
		corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions)
	}

	webhooksHandler := api.NewWebhooksHandler(logger, g.ah, g.configstoreClient, g.runserviceClient, g.c.APIExposedURL)

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
	projectCreateRunHandler := api.NewProjectCreateRunHandler(logger, g.ah)

	secretHandler := api.NewSecretHandler(logger, g.ah)
	createSecretHandler := api.NewCreateSecretHandler(logger, g.ah)
	updateSecretHandler := api.NewUpdateSecretHandler(logger, g.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(logger, g.ah)

	variableHandler := api.NewVariableHandler(logger, g.ah)
	createVariableHandler := api.NewCreateVariableHandler(logger, g.ah)
	updateVariableHandler := api.NewUpdateVariableHandler(logger, g.ah)
	deleteVariableHandler := api.NewDeleteVariableHandler(logger, g.ah)

	currentUserHandler := api.NewCurrentUserHandler(logger, g.ah)
	userHandler := api.NewUserHandler(logger, g.ah)
	usersHandler := api.NewUsersHandler(logger, g.ah)
	createUserHandler := api.NewCreateUserHandler(logger, g.ah)
	deleteUserHandler := api.NewDeleteUserHandler(logger, g.ah)
	userCreateRunHandler := api.NewUserCreateRunHandler(logger, g.ah)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, g.ah)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, g.ah)
	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, g.ah)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(logger, g.ah)

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, g.ah)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, g.ah)
	updateRemoteSourceHandler := api.NewUpdateRemoteSourceHandler(logger, g.ah)
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
	logsDeleteHandler := api.NewLogsDeleteHandler(logger, g.ah)

	userRemoteReposHandler := api.NewUserRemoteReposHandler(logger, g.ah, g.configstoreClient)

	badgeHandler := api.NewBadgeHandler(logger, g.ah)

	versionHandler := api.NewVersionHandler(logger, g.ah)

	reposHandler := api.NewReposHandler(logger, g.c.GitserverURL)

	loginUserHandler := api.NewLoginUserHandler(logger, g.ah)
	authorizeHandler := api.NewAuthorizeHandler(logger, g.ah)
	registerHandler := api.NewRegisterUserHandler(logger, g.ah)
	oauth2callbackHandler := api.NewOAuth2CallbackHandler(logger, g.ah)

	router := mux.NewRouter()
	reposRouter := mux.NewRouter()

	apirouter := mux.NewRouter().PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	authForcedHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, true)
	authOptionalHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, false)

	router.PathPrefix("/api/v1alpha").Handler(apirouter)

	apirouter.Handle("/logs", authOptionalHandler(logsHandler)).Methods("GET")
	apirouter.Handle("/logs", authForcedHandler(logsDeleteHandler)).Methods("DELETE")

	//apirouter.Handle("/projectgroups", authForcedHandler(projectsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(projectGroupHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/subgroups", authForcedHandler(projectGroupSubgroupsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/projects", authForcedHandler(projectGroupProjectsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups", authForcedHandler(createProjectGroupHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(updateProjectGroupHandler)).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}", authForcedHandler(deleteProjectGroupHandler)).Methods("DELETE")

	apirouter.Handle("/projects/{projectref}", authOptionalHandler(projectHandler)).Methods("GET")
	apirouter.Handle("/projects", authForcedHandler(createProjectHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}", authForcedHandler(updateProjectHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}", authForcedHandler(deleteProjectHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/reconfig", authForcedHandler(projectReconfigHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/updaterepolinkedaccount", authForcedHandler(projectUpdateRepoLinkedAccountHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/createrun", authForcedHandler(projectCreateRunHandler)).Methods("POST")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(secretHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(secretHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", authForcedHandler(updateSecretHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", authForcedHandler(updateSecretHandler)).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", authForcedHandler(variableHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", authForcedHandler(variableHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables", authForcedHandler(createVariableHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/variables", authForcedHandler(createVariableHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", authForcedHandler(updateVariableHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", authForcedHandler(updateVariableHandler)).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/variables/{variablename}", authForcedHandler(deleteVariableHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/variables/{variablename}", authForcedHandler(deleteVariableHandler)).Methods("DELETE")

	apirouter.Handle("/user", authForcedHandler(currentUserHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}", authForcedHandler(userHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(usersHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(createUserHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}", authForcedHandler(deleteUserHandler)).Methods("DELETE")
	apirouter.Handle("/user/createrun", authForcedHandler(userCreateRunHandler)).Methods("POST")

	apirouter.Handle("/users/{userref}/linkedaccounts", authForcedHandler(createUserLAHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", authForcedHandler(deleteUserLAHandler)).Methods("DELETE")
	apirouter.Handle("/users/{userref}/tokens", authForcedHandler(createUserTokenHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/tokens/{tokenname}", authForcedHandler(deleteUserTokenHandler)).Methods("DELETE")

	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(remoteSourceHandler)).Methods("GET")
	apirouter.Handle("/remotesources", authForcedHandler(createRemoteSourceHandler)).Methods("POST")
	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(updateRemoteSourceHandler)).Methods("PUT")
	apirouter.Handle("/remotesources", authOptionalHandler(remoteSourcesHandler)).Methods("GET")
	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(deleteRemoteSourceHandler)).Methods("DELETE")

	apirouter.Handle("/orgs/{orgref}", authForcedHandler(orgHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(orgsHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(createOrgHandler)).Methods("POST")
	apirouter.Handle("/orgs/{orgref}", authForcedHandler(deleteOrgHandler)).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/members", authForcedHandler(orgMembersHandler)).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(addOrgMemberHandler)).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(removeOrgMemberHandler)).Methods("DELETE")

	apirouter.Handle("/runs/{runid}", authOptionalHandler(runHandler)).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", authForcedHandler(runActionsHandler)).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}", authOptionalHandler(runtaskHandler)).Methods("GET")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", authForcedHandler(runTaskActionsHandler)).Methods("PUT")
	apirouter.Handle("/runs", authForcedHandler(runsHandler)).Methods("GET")

	apirouter.Handle("/user/remoterepos/{remotesourceref}", authForcedHandler(userRemoteReposHandler)).Methods("GET")

	apirouter.Handle("/badges/{projectref}", badgeHandler).Methods("GET")

	apirouter.Handle("/version", versionHandler).Methods("GET")

	apirouter.Handle("/auth/login", loginUserHandler).Methods("POST")
	apirouter.Handle("/auth/authorize", authorizeHandler).Methods("POST")
	apirouter.Handle("/auth/register", registerHandler).Methods("POST")
	apirouter.Handle("/auth/oauth2/callback", oauth2callbackHandler).Methods("GET")

	// TODO(sgotti) add auth to these requests
	reposRouter.Handle("/repos/{rest:.*}", reposHandler).Methods("GET", "POST")

	router.Handle("/webhooks", webhooksHandler).Methods("POST")
	router.PathPrefix("/").HandlerFunc(handlers.NewWebBundleHandlerFunc(g.c.APIExposedURL))

	maxBytesHandler := handlers.NewMaxBytesHandler(router, maxRequestSize)

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/repos/").Handler(corsHandler(reposRouter))
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
	case err := <-lerrCh:
		if err != nil {
			log.Errorf("http server listen error: %v", err)
			return err
		}
	}

	return nil
}
