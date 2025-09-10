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
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/csrf"
	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"

	icommon "agola.io/agola/internal/common"
	"agola.io/agola/internal/objectstorage"
	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/gateway/api"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/services/gateway/handlers"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	nsclient "agola.io/agola/services/notification/client"
	rsclient "agola.io/agola/services/runservice/client"
)

const (
	maxRequestSize = 1024 * 1024
)

type Gateway struct {
	log                zerolog.Logger
	c                  *config.Gateway
	corsAllowedOrigins []string
	csrfTrustedOrigins []string

	ost                objectstorage.ObjStorage
	runserviceClient   *rsclient.Client
	configstoreClient  *csclient.Client
	notificationClient *nsclient.Client
	ah                 *action.ActionHandler
	sd                 *scommon.TokenSigningData
	sc                 *scommon.CookieSigningData
}

func NewGateway(ctx context.Context, log zerolog.Logger, gc *config.Config) (*Gateway, error) {
	c := &gc.Gateway

	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
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

	corsAllowedOrigins := []string{}
	// gorilla CSRF trusted origins are a list of host[:port]. Convert web.AllowedOrigins urls to this list. Assume AllowedOrigins are valid urls (no wildcards)
	csrfTrustedOrigins := []string{}
	for _, allowedOrigin := range c.Web.AllowedOrigins {
		u, err := url.Parse(allowedOrigin)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		urls := util.ExpandURLDefaultPorts(u)

		for _, u := range urls {
			corsAllowedOrigins = append(corsAllowedOrigins, u.String())
			csrfTrustedOrigins = append(csrfTrustedOrigins, u.Host)
		}
	}

	sd := &scommon.TokenSigningData{Duration: c.TokenSigning.Duration}
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
		privateKeyData, err := os.ReadFile(c.TokenSigning.PrivateKeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading token signing private key")
		}
		sd.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing token signing private key")
		}
		publicKeyData, err := os.ReadFile(c.TokenSigning.PublicKeyPath)
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

	sc := scommon.NewCookieSigningData(&scommon.CookieSigningConfig{
		Duration: c.CookieSigning.Duration,
		Key:      c.CookieSigning.Key,
	})

	ost, err := icommon.NewObjectStorage(ctx, &c.ObjectStorage)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	configstoreClient := csclient.NewClient(c.ConfigstoreURL, c.ConfigstoreAPIToken)
	runserviceClient := rsclient.NewClient(c.RunserviceURL, c.RunserviceAPIToken)
	notificationClient := nsclient.NewClient(c.NotificationURL, c.NotificationAPIToken)

	ah := action.NewActionHandler(log, sd, sc, configstoreClient, runserviceClient, notificationClient, gc.ID, c.APIExposedURL, c.WebExposedURL, c.UnsecureCookies, action.OrganizationMemberAddingMode(c.OrganizationMemberAddingMode))

	return &Gateway{
		log:                log,
		c:                  c,
		corsAllowedOrigins: corsAllowedOrigins,
		csrfTrustedOrigins: csrfTrustedOrigins,
		ost:                ost,
		runserviceClient:   runserviceClient,
		configstoreClient:  configstoreClient,
		notificationClient: notificationClient,
		ah:                 ah,
		sd:                 sd,
		sc:                 sc,
	}, nil
}

func (g *Gateway) Run(ctx context.Context) error {
	// noop coors handler
	corsHandler := func(h http.Handler) http.Handler {
		return h
	}

	if len(g.corsAllowedOrigins) > 0 {
		corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
		corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Content-Length", "Content-Type", "Content-Range", "X-Csrf-Token", "X-Agola-Cursor", "Authorization"})
		corsAllowedOriginsOptions := ghandlers.AllowedOrigins(g.corsAllowedOrigins)
		corsExposeHeadersOptions := ghandlers.ExposedHeaders([]string{"X-Csrf-Token", "X-Agola-Cursor"})
		corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions, corsExposeHeadersOptions, ghandlers.AllowCredentials())
	}

	csrfCookieName := common.CSRFCookieName(g.c.UnsecureCookies)
	// make the csrf cookie max age 0 so it'll be a session cookie and won't expire.
	csrfCookieMaxAge := 0

	protectCSRF := csrf.Protect([]byte(g.c.CookieSigning.Key), csrf.Path("/"), csrf.CookieName(csrfCookieName), csrf.MaxAge(csrfCookieMaxAge), csrf.Secure(!g.c.UnsecureCookies), csrf.TrustedOrigins(g.csrfTrustedOrigins), csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// on failed csrf return a csrf token so next request will have it
		w.Header().Set("X-Csrf-Token", csrf.Token(r))

		http.Error(w, fmt.Sprintf("%s - %s",
			http.StatusText(http.StatusForbidden), csrf.FailureReason(r)),
			http.StatusForbidden)
	})))

	skipCSRFOnToken := handlers.NewSkipCSRFOnTokenAuth(g.log)
	setCSRFHeader := handlers.NewSetCSRFHeader(g.log)

	CSRF := func(h http.Handler) http.Handler {
		return skipCSRFOnToken(protectCSRF(setCSRFHeader(h)))
	}

	webhooksHandler := api.NewWebhooksHandler(g.log, g.ah, g.configstoreClient, g.runserviceClient, g.c.APIExposedURL)

	projectGroupHandler := api.NewProjectGroupHandler(g.log, g.ah)
	projectGroupSubgroupsHandler := api.NewProjectGroupSubgroupsHandler(g.log, g.ah)
	projectGroupProjectsHandler := api.NewProjectGroupProjectsHandler(g.log, g.ah)
	createProjectGroupHandler := api.NewCreateProjectGroupHandler(g.log, g.ah)
	updateProjectGroupHandler := api.NewUpdateProjectGroupHandler(g.log, g.ah)
	deleteProjectGroupHandler := api.NewDeleteProjectGroupHandler(g.log, g.ah)

	projectHandler := api.NewProjectHandler(g.log, g.ah)
	createProjectHandler := api.NewCreateProjectHandler(g.log, g.ah)
	updateProjectHandler := api.NewUpdateProjectHandler(g.log, g.ah)
	deleteProjectHandler := api.NewDeleteProjectHandler(g.log, g.ah)
	projectReconfigHandler := api.NewProjectReconfigHandler(g.log, g.ah)
	projectUpdateRepoLinkedAccountHandler := api.NewProjectUpdateRepoLinkedAccountHandler(g.log, g.ah)
	projectCreateRunHandler := api.NewProjectCreateRunHandler(g.log, g.ah)
	refreshRemoteRepositoryInfoHandler := api.NewRefreshRemoteRepositoryInfoHandler(g.log, g.ah)
	projectRunWebhookDeliveriesHandler := api.NewProjectRunWebhookDeliveriesHandler(g.log, g.ah)
	projectRunWebhookRedeliveryHandler := api.NewProjectRunWebhookRedeliveryHandler(g.log, g.ah)
	projectCommitStatusDeliveriesHandler := api.NewProjectCommitStatusDeliveriesHandler(g.log, g.ah)
	projectCommitStatusRedeliveryHandler := api.NewProjectCommitStatusRedeliveryHandler(g.log, g.ah)

	secretsHandler := api.NewSecretsHandler(g.log, g.ah)
	createSecretHandler := api.NewCreateSecretHandler(g.log, g.ah)
	updateSecretHandler := api.NewUpdateSecretHandler(g.log, g.ah)
	deleteSecretHandler := api.NewDeleteSecretHandler(g.log, g.ah)

	variablesHandler := api.NewVariablesHandler(g.log, g.ah)
	createVariableHandler := api.NewCreateVariableHandler(g.log, g.ah)
	updateVariableHandler := api.NewUpdateVariableHandler(g.log, g.ah)
	deleteVariableHandler := api.NewDeleteVariableHandler(g.log, g.ah)

	currentUserHandler := api.NewCurrentUserHandler(g.log, g.ah)
	userHandler := api.NewUserHandler(g.log, g.ah)
	usersHandler := api.NewUsersHandler(g.log, g.ah)
	createUserHandler := api.NewCreateUserHandler(g.log, g.ah)
	deleteUserHandler := api.NewDeleteUserHandler(g.log, g.ah)
	userCreateRunHandler := api.NewUserCreateRunHandler(g.log, g.ah)
	userOrgsHandler := api.NewUserOrgsHandler(g.log, g.ah)
	userOrgInvitationsHandler := api.NewUserOrgInvitationsHandler(g.log, g.ah)
	userOrgInvitationActionHandler := api.NewUserOrgInvitationActionHandler(g.log, g.ah)

	createUserLAHandler := api.NewCreateUserLAHandler(g.log, g.ah)
	deleteUserLAHandler := api.NewDeleteUserLAHandler(g.log, g.ah)
	createUserTokenHandler := api.NewCreateUserTokenHandler(g.log, g.ah)
	deleteUserTokenHandler := api.NewDeleteUserTokenHandler(g.log, g.ah)

	remoteSourceHandler := api.NewRemoteSourceHandler(g.log, g.ah)
	createRemoteSourceHandler := api.NewCreateRemoteSourceHandler(g.log, g.ah)
	updateRemoteSourceHandler := api.NewUpdateRemoteSourceHandler(g.log, g.ah)
	remoteSourcesHandler := api.NewRemoteSourcesHandler(g.log, g.ah)
	deleteRemoteSourceHandler := api.NewDeleteRemoteSourceHandler(g.log, g.ah)

	orgHandler := api.NewOrgHandler(g.log, g.ah)
	orgsHandler := api.NewOrgsHandler(g.log, g.ah)
	createOrgHandler := api.NewCreateOrgHandler(g.log, g.ah)
	updateOrgHandler := api.NewUpdateOrgHandler(g.log, g.ah)
	deleteOrgHandler := api.NewDeleteOrgHandler(g.log, g.ah)
	createOrgInvitationHandler := api.NewCreateOrgInvitationHandler(g.log, g.ah)
	orgInvitationsHandler := api.NewOrgInvitationsHandler(g.log, g.ah)
	orgInvitationHandler := api.NewOrgInvitationHandler(g.log, g.ah)
	deleteOrgInvitationHandler := api.NewDeleteOrgInvitationHandler(g.log, g.ah)

	orgMembersHandler := api.NewOrgMembersHandler(g.log, g.ah)
	addOrgMemberHandler := api.NewAddOrgMemberHandler(g.log, g.ah)
	removeOrgMemberHandler := api.NewRemoveOrgMemberHandler(g.log, g.ah)

	projectRunsHandler := api.NewGroupRunsHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRunHandler := api.NewGroupRunHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRuntaskHandler := api.NewRuntaskHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRunActionsHandler := api.NewRunActionsHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRunTaskActionsHandler := api.NewRunTaskActionsHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRunLogsHandler := api.NewLogsHandler(g.log, g.ah, scommon.GroupTypeProject)
	projectRunLogsDeleteHandler := api.NewLogsDeleteHandler(g.log, g.ah, scommon.GroupTypeProject)

	userRunsHandler := api.NewGroupRunsHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRunHandler := api.NewGroupRunHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRuntaskHandler := api.NewRuntaskHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRunActionsHandler := api.NewRunActionsHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRunTaskActionsHandler := api.NewRunTaskActionsHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRunLogsHandler := api.NewLogsHandler(g.log, g.ah, scommon.GroupTypeUser)
	userRunLogsDeleteHandler := api.NewLogsDeleteHandler(g.log, g.ah, scommon.GroupTypeUser)

	userRemoteReposHandler := api.NewUserRemoteReposHandler(g.log, g.ah, g.configstoreClient)

	badgeHandler := api.NewBadgeHandler(g.log, g.ah)

	versionHandler := api.NewVersionHandler(g.log, g.ah)

	reposHandler := api.NewReposHandler(g.log, g.c.GitserverURL, g.c.GitserverAPIToken)

	loginUserHandler := api.NewLoginUserHandler(g.log, g.ah)
	authorizeHandler := api.NewAuthorizeHandler(g.log, g.ah)
	registerHandler := api.NewRegisterUserHandler(g.log, g.ah)
	oauth2callbackHandler := api.NewOAuth2CallbackHandler(g.log, g.ah)

	maintenanceStatusHandler := api.NewMaintenanceStatusHandler(g.log, g.ah)
	maintenanceModeHandler := api.NewMaintenanceModeHandler(g.log, g.ah)
	exportHandler := api.NewExportHandler(g.log, g.ah)
	importHandler := api.NewImportHandler(g.log, g.ah)

	router := mux.NewRouter()
	reposRouter := mux.NewRouter()

	apirouter := mux.NewRouter().PathPrefix("/api/v1alpha").Subrouter().UseEncodedPath()

	authForcedHandler := func(h http.Handler) http.Handler {
		// first do auth, then check csrf (skipping it only on successful token auth)
		return handlers.NewAuthChecker(g.log, g.configstoreClient, handlers.WithTokenChecker(g.c.AdminToken), handlers.WithCookieChecker(g.sc, g.c.UnsecureCookies), handlers.WithRequired(true))(CSRF(h))
	}
	authOptionalHandler := func(h http.Handler) http.Handler {
		// first do auth, then check csrf (skipping it only on successful token auth)
		return handlers.NewAuthChecker(g.log, g.configstoreClient, handlers.WithTokenChecker(g.c.AdminToken), handlers.WithCookieChecker(g.sc, g.c.UnsecureCookies), handlers.WithRequired(false))(CSRF(h))
	}

	router.PathPrefix("/api/v1alpha").Handler(apirouter)

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
	apirouter.Handle("/projects/{projectref}/runs", authForcedHandler(projectRunsHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}", authOptionalHandler(projectRunHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}/actions", authForcedHandler(projectRunActionsHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}/tasks/{taskid}", authOptionalHandler(projectRuntaskHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}/tasks/{taskid}/actions", authForcedHandler(projectRunTaskActionsHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}/tasks/{taskid}/logs", authOptionalHandler(projectRunLogsHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/runs/{runnumber}/tasks/{taskid}/logs", authForcedHandler(projectRunLogsDeleteHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/refreshremoterepo", authForcedHandler(refreshRemoteRepositoryInfoHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/runwebhookdeliveries", authForcedHandler(projectRunWebhookDeliveriesHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/runwebhookdeliveries/{runwebhookdeliveryid}/redelivery", authForcedHandler(projectRunWebhookRedeliveryHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/commitstatusdeliveries", authForcedHandler(projectCommitStatusDeliveriesHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/commitstatusdeliveries/{commitstatusdeliveryid}/redelivery", authForcedHandler(projectCommitStatusRedeliveryHandler)).Methods("PUT")

	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(secretsHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(secretsHandler)).Methods("GET")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projects/{projectref}/secrets", authForcedHandler(createSecretHandler)).Methods("POST")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", authForcedHandler(updateSecretHandler)).Methods("PUT")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", authForcedHandler(updateSecretHandler)).Methods("PUT")
	apirouter.Handle("/projectgroups/{projectgroupref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")
	apirouter.Handle("/projects/{projectref}/secrets/{secretname}", authForcedHandler(deleteSecretHandler)).Methods("DELETE")

	apirouter.Handle("/projectgroups/{projectgroupref}/variables", authForcedHandler(variablesHandler)).Methods("GET")
	apirouter.Handle("/projects/{projectref}/variables", authForcedHandler(variablesHandler)).Methods("GET")
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
	apirouter.Handle("/user/orgs", authForcedHandler(userOrgsHandler)).Methods("GET")
	apirouter.Handle("/user/org_invitations", authForcedHandler(userOrgInvitationsHandler)).Methods("GET")
	apirouter.Handle("/user/org_invitations/{orgref}/actions", authForcedHandler(userOrgInvitationActionHandler)).Methods("PUT")

	apirouter.Handle("/users/{userref}/runs", authForcedHandler(userRunsHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}/runs/{runnumber}", authOptionalHandler(userRunHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}/runs/{runnumber}/actions", authForcedHandler(userRunActionsHandler)).Methods("PUT")
	apirouter.Handle("/users/{userref}/runs/{runnumber}/tasks/{taskid}", authOptionalHandler(userRuntaskHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}/runs/{runnumber}/tasks/{taskid}/actions", authForcedHandler(userRunTaskActionsHandler)).Methods("PUT")
	apirouter.Handle("/users/{userref}/runs/{runnumber}/tasks/{taskid}/logs", authOptionalHandler(userRunLogsHandler)).Methods("GET")
	apirouter.Handle("/users/{userref}/runs/{runnumber}/tasks/{taskid}/logs", authForcedHandler(userRunLogsDeleteHandler)).Methods("DELETE")

	apirouter.Handle("/users/{userref}/linkedaccounts", authForcedHandler(createUserLAHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/linkedaccounts/{laid}", authForcedHandler(deleteUserLAHandler)).Methods("DELETE")
	apirouter.Handle("/users/{userref}/tokens", authForcedHandler(createUserTokenHandler)).Methods("POST")
	apirouter.Handle("/users/{userref}/tokens/{tokenname}", authForcedHandler(deleteUserTokenHandler)).Methods("DELETE")

	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(remoteSourceHandler)).Methods("GET")
	apirouter.Handle("/remotesources", authForcedHandler(createRemoteSourceHandler)).Methods("POST")
	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(updateRemoteSourceHandler)).Methods("PUT")
	apirouter.Handle("/remotesources", remoteSourcesHandler).Methods("GET")
	apirouter.Handle("/remotesources/{remotesourceref}", authForcedHandler(deleteRemoteSourceHandler)).Methods("DELETE")

	apirouter.Handle("/orgs/{orgref}", authForcedHandler(orgHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(orgsHandler)).Methods("GET")
	apirouter.Handle("/orgs", authForcedHandler(createOrgHandler)).Methods("POST")
	apirouter.Handle("/orgs/{orgref}", authForcedHandler(updateOrgHandler)).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}", authForcedHandler(deleteOrgHandler)).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/members", authForcedHandler(orgMembersHandler)).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(addOrgMemberHandler)).Methods("PUT")
	apirouter.Handle("/orgs/{orgref}/members/{userref}", authForcedHandler(removeOrgMemberHandler)).Methods("DELETE")
	apirouter.Handle("/orgs/{orgref}/invitations", authForcedHandler(orgInvitationsHandler)).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/invitations", authForcedHandler(createOrgInvitationHandler)).Methods("POST")
	apirouter.Handle("/orgs/{orgref}/invitations/{userref}", authForcedHandler(orgInvitationHandler)).Methods("GET")
	apirouter.Handle("/orgs/{orgref}/invitations/{userref}", authForcedHandler(deleteOrgInvitationHandler)).Methods("DELETE")

	apirouter.Handle("/user/remoterepos/{remotesourceref}", authForcedHandler(userRemoteReposHandler)).Methods("GET")

	apirouter.Handle("/badges/{projectref}", badgeHandler).Methods("GET")

	apirouter.Handle("/version", versionHandler).Methods("GET")

	apirouter.Handle("/auth/login", loginUserHandler).Methods("POST")
	apirouter.Handle("/auth/authorize", authorizeHandler).Methods("POST")
	apirouter.Handle("/auth/register", registerHandler).Methods("POST")
	apirouter.Handle("/auth/oauth2/callback", oauth2callbackHandler).Methods("GET")

	apirouter.Handle("/maintenance/{servicename}", authForcedHandler(maintenanceStatusHandler)).Methods("GET")
	apirouter.Handle("/maintenance/{servicename}", authForcedHandler(maintenanceModeHandler)).Methods("PUT", "DELETE")
	apirouter.Handle("/export/{servicename}", authForcedHandler(exportHandler)).Methods("GET")
	apirouter.Handle("/import/{servicename}", authForcedHandler(importHandler)).Methods("POST")

	// TODO(sgotti) add auth to these requests
	reposRouter.Handle("/repos/{rest:.*}", reposHandler).Methods("GET", "POST")

	router.Handle("/webhooks", webhooksHandler).Methods("POST")
	router.PathPrefix("/").HandlerFunc(handlers.NewWebBundleHandlerFunc(g.c.APIExposedURL))

	maxBytesHandler := handlers.NewMaxBytesHandler(router, maxRequestSize)

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/repos/").Handler(corsHandler(reposRouter))
	mainrouter.PathPrefix("/").Handler(ghandlers.RecoveryHandler(ghandlers.PrintRecoveryStack(true))(corsHandler(maxBytesHandler)))

	var tlsConfig *tls.Config
	if g.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(g.c.Web.TLSCertFile, g.c.Web.TLSKeyFile, "", false)
		if err != nil {
			g.log.Err(err).Send()
			return errors.WithStack(err)
		}
	}

	httpServer := http.Server{
		Addr:      g.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error)
	go func() {
		if !g.c.Web.TLS {
			lerrCh <- httpServer.ListenAndServe()
		} else {
			lerrCh <- httpServer.ListenAndServeTLS("", "")
		}
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("configstore exiting")
		httpServer.Close()
	case err := <-lerrCh:
		if err != nil {
			log.Err(err).Msg("http server listen error")
			return errors.WithStack(err)
		}
	}

	return nil
}
