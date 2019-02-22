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

	scommon "github.com/sorintlab/agola/internal/common"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/config"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/gateway/handlers"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
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

type Gateway struct {
	c *config.Gateway

	lts               *objectstorage.ObjStorage
	runserviceClient  *rsapi.Client
	configstoreClient *csapi.Client
	ch                *command.CommandHandler
	sd                *common.TokenSigningData
}

func NewGateway(c *config.Gateway) (*Gateway, error) {
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

	lts, err := scommon.NewLTS(&c.LTS)
	if err != nil {
		return nil, err
	}

	configstoreClient := csapi.NewClient(c.ConfigStoreURL)

	ch := command.NewCommandHandler(logger, sd, configstoreClient, c.APIExposedURL, c.WebExposedURL)

	return &Gateway{
		c:                 c,
		lts:               lts,
		runserviceClient:  rsapi.NewClient(c.RunServiceURL),
		configstoreClient: configstoreClient,
		ch:                ch,
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

	webhooksHandler := &webhooksHandler{log: log, configstoreClient: g.configstoreClient, runserviceClient: g.runserviceClient, apiExposedURL: g.c.APIExposedURL}

	projectHandler := api.NewProjectHandler(logger, g.configstoreClient)
	projectByNameHandler := api.NewProjectByNameHandler(logger, g.configstoreClient)
	projectsHandler := api.NewProjectsHandler(logger, g.configstoreClient)
	createProjectHandler := api.NewCreateProjectHandler(logger, g.ch, g.configstoreClient, g.c.APIExposedURL)
	deleteProjectHandler := api.NewDeleteProjectHandler(logger, g.configstoreClient)
	projectReconfigHandler := api.NewProjectReconfigHandler(logger, g.ch, g.configstoreClient, g.c.APIExposedURL)

	currentUserHandler := api.NewCurrentUserHandler(logger, g.configstoreClient)
	userHandler := api.NewUserHandler(logger, g.configstoreClient)
	userByNameHandler := api.NewUserByNameHandler(logger, g.configstoreClient)
	usersHandler := api.NewUsersHandler(logger, g.configstoreClient)
	createUserHandler := api.NewCreateUserHandler(logger, g.configstoreClient)
	deleteUserHandler := api.NewDeleteUserHandler(logger, g.configstoreClient)

	createUserLAHandler := api.NewCreateUserLAHandler(logger, g.ch, g.configstoreClient)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(logger, g.configstoreClient)
	createUserTokenHandler := api.NewCreateUserTokenHandler(logger, g.configstoreClient)

	remoteSourceHandler := api.NewRemoteSourceHandler(logger, g.configstoreClient)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(logger, g.configstoreClient)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(logger, g.configstoreClient)

	runHandler := api.NewRunHandler(logger, g.runserviceClient)
	runsHandler := api.NewRunsHandler(logger, g.runserviceClient)
	runtaskHandler := api.NewRuntaskHandler(logger, g.runserviceClient)

	logsHandler := api.NewLogsHandler(logger, g.runserviceClient)

	reposHandler := api.NewReposHandler(logger, g.configstoreClient)

	loginUserHandler := api.NewLoginUserHandler(logger, g.ch, g.configstoreClient)
	oauth2callbackHandler := api.NewOAuth2CallbackHandler(logger, g.ch, g.configstoreClient)

	router := mux.NewRouter()

	apirouter := mux.NewRouter().PathPrefix("/api/v1alpha").Subrouter()

	authForcedHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, true)
	authOptionalHandler := handlers.NewAuthHandler(logger, g.configstoreClient, g.c.AdminToken, g.sd, false)

	router.PathPrefix("/api/v1alpha").Handler(apirouter)

	apirouter.Handle("/logs", logsHandler).Methods("GET")

	apirouter.Handle("/project/{projectid}", authForcedHandler(projectHandler)).Methods("GET")
	apirouter.Handle("/projects", authForcedHandler(projectsHandler)).Methods("GET")
	apirouter.Handle("/projects", authForcedHandler(createProjectHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectname}", authForcedHandler(projectByNameHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectname}", authForcedHandler(deleteProjectHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectname}/reconfig", authForcedHandler(projectReconfigHandler)).Methods("POST")

	apirouter.Handle("/user", authForcedHandler(currentUserHandler)).Methods("GET")
	apirouter.Handle("/user/{userid}", authForcedHandler(userHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(usersHandler)).Methods("GET")
	apirouter.Handle("/users", authForcedHandler(createUserHandler)).Methods("PUT")
	apirouter.Handle("/users/{username}", authForcedHandler(userByNameHandler)).Methods("GET")
	apirouter.Handle("/users/{username}", authForcedHandler(deleteUserHandler)).Methods("DELETE")

	apirouter.Handle("/users/{username}/linkedaccounts", authForcedHandler(createUserLAHandler)).Methods("PUT")
	apirouter.Handle("/users/{username}/linkedaccounts/{laid}", authForcedHandler(deleteUserLAHandler)).Methods("DELETE")
	apirouter.Handle("/users/{username}/tokens", authForcedHandler(createUserTokenHandler)).Methods("PUT")

	apirouter.Handle("/remotesource/{id}", authForcedHandler(remoteSourceHandler)).Methods("GET")
	apirouter.Handle("/remotesources", authForcedHandler(createRemoteSourceHandler)).Methods("PUT")
	apirouter.Handle("/remotesources", authOptionalHandler(remoteSourcesHandler)).Methods("GET")

	apirouter.Handle("/run/{runid}", authForcedHandler(runHandler)).Methods("GET")
	apirouter.Handle("/run/{runid}/task/{taskid}", authForcedHandler(runtaskHandler)).Methods("GET")
	apirouter.Handle("/runs", authForcedHandler(runsHandler)).Methods("GET")

	router.Handle("/login", loginUserHandler).Methods("POST")
	router.Handle("/oauth2/callback", oauth2callbackHandler).Methods("GET")

	router.Handle("/repos/{rest:.*}", reposHandler).Methods("GET", "POST")

	router.Handle("/webhooks", webhooksHandler).Methods("POST")
	router.PathPrefix("/").HandlerFunc(handlers.NewWebBundleHandlerFunc(g.c.APIExposedURL))

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(corsHandler(router))

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
