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

package config

import (
	"os"
	"time"

	"github.com/sorintlab/errors"
	yaml "gopkg.in/yaml.v2"

	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
)

const (
	maxIDLength                         = 20
	defaultOrganizationMemberAddingMode = OrganizationMemberAddingModeDirect
)

type Config struct {
	// ID defines the agola installation id. It's used inside the
	// various services to uniquely distinguish it from other installations
	// Defaults to "agola"
	ID string `yaml:"id"`

	Gateway      Gateway      `yaml:"gateway"`
	Scheduler    Scheduler    `yaml:"scheduler"`
	Notification Notification `yaml:"notification"`
	Runservice   Runservice   `yaml:"runservice"`
	Executor     Executor     `yaml:"executor"`
	Configstore  Configstore  `yaml:"configstore"`
	Gitserver    Gitserver    `yaml:"gitserver"`

	// Global urls to avoid repeating them for every service

	// APIExposedURL is the gateway API exposed url i.e. https://myagola.example.com
	APIExposedURL string `yaml:"apiExposedURL"`

	// WebExposedURL is the web interface exposed url i.e. https://myagola.example.com
	// This is used for generating the redirect_url in oauth2 redirects
	WebExposedURL string `yaml:"webExposedURL"`

	RunserviceURL  string `yaml:"runserviceURL"`
	ConfigstoreURL string `yaml:"configstoreURL"`
	GitserverURL   string `yaml:"gitserverURL"`

	// InternalServicesAPIToken is a global api token for internal services (for
	// both servers and clients)
	// Used when a specific token isn't defined
	InternalServicesAPIToken string `yaml:"internalServicesAPIToken"`

	// Global internal services api tokens to avoid repeating them for every
	// service (for both servers and clients)
	// If empty their value will be set to InternalServicesAPIToken
	RunserviceAPIToken  string `yaml:"runserviceAPIToken"`
	ExecutorAPIToken    string `yaml:"executorAPIToken"`
	ConfigstoreAPIToken string `yaml:"configstoreAPIToken"`
	GitserverAPIToken   string `yaml:"gitserverAPIToken"`
}

type Gateway struct {
	Debug bool `yaml:"debug"`

	// APIExposedURL is the gateway API exposed url i.e. https://myagola.example.com
	APIExposedURL string `yaml:"apiExposedURL"`

	// WebExposedURL is the web interface exposed url i.e. https://myagola.example.com
	// This is used for generating the redirect_url in oauth2 redirects
	WebExposedURL string `yaml:"webExposedURL"`

	RunserviceURL       string `yaml:"runserviceURL"`
	RunserviceAPIToken  string `yaml:"runserviceAPIToken"`
	ConfigstoreURL      string `yaml:"configstoreURL"`
	ConfigstoreAPIToken string `yaml:"configstoreAPIToken"`
	GitserverURL        string `yaml:"gitserverURL"`
	GitserverAPIToken   string `yaml:"gitserverAPIToken"`

	Web           Web           `yaml:"web"`
	ObjectStorage ObjectStorage `yaml:"objectStorage"`

	TokenSigning  TokenSigning  `yaml:"tokenSigning"`
	CookieSigning CookieSigning `yaml:"cookieSigning"`

	// when true will not set __Host/__Secure and Secure cookies. Should be set only for local development over http
	UnsecureCookies bool `yaml:"unsecureCookies"`

	AdminToken string `yaml:"adminToken"`

	OrganizationMemberAddingMode OrganizationMemberAddingMode `yaml:"organizationMemberAddingMode"`
}

type Scheduler struct {
	Debug bool `yaml:"debug"`

	RunserviceURL      string `yaml:"runserviceURL"`
	RunserviceAPIToken string `yaml:"runserviceAPIToken"`
}

type Notification struct {
	Debug bool `yaml:"debug"`

	// WebExposedURL is the web interface exposed url i.e. https://myagola.example.com
	// This is used for generating the redirect_url in oauth2 redirects
	WebExposedURL string `yaml:"webExposedURL"`

	RunserviceURL      string `yaml:"runserviceURL"`
	RunserviceAPIToken string `yaml:"runserviceAPIToken"`

	ConfigstoreURL      string `yaml:"configstoreURL"`
	ConfigstoreAPIToken string `yaml:"configstoreAPIToken"`

	DB DB `yaml:"db"`

	WebhookURL    string `yaml:"webhookURL"`
	WebhookSecret string `yaml:"webhookSecret"`
}

type Runservice struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	DB DB `yaml:"db"`

	Web Web `yaml:"web"`

	APIToken string `yaml:"apiToken"`

	ExecutorAPIToken string `yaml:"executorAPIToken"`

	ObjectStorage ObjectStorage `yaml:"objectStorage"`

	RunCacheExpireInterval     time.Duration `yaml:"runCacheExpireInterval"`
	RunWorkspaceExpireInterval time.Duration `yaml:"runWorkspaceExpireInterval"`
	RunLogExpireInterval       time.Duration `yaml:"runLogExpireInterval"`
}

type Executor struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	RunserviceURL      string `yaml:"runserviceURL"`
	RunserviceAPIToken string `yaml:"runserviceAPIToken"`

	ToolboxPath string `yaml:"toolboxPath"`

	Web Web `yaml:"web"`

	APIToken string `yaml:"apiToken"`

	Driver Driver `yaml:"driver"`

	InitImage InitImage `yaml:"initImage"`

	Labels map[string]string `yaml:"labels"`
	// ActiveTasksLimit is the max number of concurrent active tasks
	ActiveTasksLimit int `yaml:"activeTasksLimit"`

	AllowPrivilegedContainers bool `yaml:"allowPrivilegedContainers"`
}

type InitImage struct {
	Image string `yaml:"image"`

	Auth *DockerRegistryAuth `yaml:"auth"`
}

type DockerRegistryAuthType string

const (
	DockerRegistryAuthTypeBasic       DockerRegistryAuthType = "basic"
	DockerRegistryAuthTypeEncodedAuth DockerRegistryAuthType = "encodedauth"
)

type DockerRegistryAuth struct {
	Type DockerRegistryAuthType `yaml:"type"`

	// basic auth
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// encoded auth string
	Auth string `yaml:"auth"`

	// future auths like aws ecr auth
}

type Configstore struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	DB DB `yaml:"db"`

	Web Web `yaml:"web"`

	APIToken string `yaml:"apiToken"`

	ObjectStorage ObjectStorage `yaml:"objectStorage"`
}

type Gitserver struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	Web Web `yaml:"web"`

	APIToken string `yaml:"apiToken"`

	ObjectStorage ObjectStorage `yaml:"objectStorage"`

	RepositoryCleanupInterval    time.Duration `yaml:"repositoryCleanupInterval"`
	RepositoryRefsExpireInterval time.Duration `yaml:"repositoryRefsExpireInterval"`
}

type Web struct {
	// http listen addess
	ListenAddress string `yaml:"listenAddress"`

	// use TLS (https)
	TLS bool `yaml:"tls"`
	// TLSCert is the path to the pem formatted server certificate. If the
	// certificate is signed by a certificate authority, the certFile should be
	// the concatenation of the server's certificate, any intermediates, and the
	// CA's certificate.
	TLSCertFile string `yaml:"tlsCertFile"`
	// Server cert private key
	// TODO(sgotti) support encrypted private keys (add a private key password config entry)
	TLSKeyFile string `yaml:"tlsKeyFile"`

	// CORS allowed origins
	AllowedOrigins []string `yaml:"allowedOrigins"`
}

type DB struct {
	Type       sql.Type `yaml:"type"`
	ConnString string   `yaml:"connString"`
}

type ObjectStorageType string

const (
	ObjectStorageTypePosix ObjectStorageType = "posix"
	ObjectStorageTypeS3    ObjectStorageType = "s3"
)

type ObjectStorage struct {
	Type ObjectStorageType `yaml:"type"`

	// Posix
	Path string `yaml:"path"`

	// S3
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	Location        string `yaml:"location"`
	AccessKey       string `yaml:"accessKey"`
	SecretAccessKey string `yaml:"secretAccessKey"`
	DisableTLS      bool   `yaml:"disableTLS"`
}

type DriverType string

const (
	DriverTypeDocker DriverType = "docker"
	DriverTypeK8s    DriverType = "kubernetes"
)

type Driver struct {
	Type DriverType `yaml:"type"`

	// docker fields

	// k8s fields

}

type TokenSigning struct {
	// token duration (defaults to 12 hours)
	Duration time.Duration `yaml:"duration"`
	// signing method: "hmac" or "rsa"
	Method string `yaml:"method"`
	// signing key. Used only with HMAC signing method
	Key string `yaml:"key"`
	// path to a file containing a pem encoded private key. Used only with RSA signing method
	PrivateKeyPath string `yaml:"privateKeyPath"`
	// path to a file containing a pem encoded public key. Used only with RSA signing method
	PublicKeyPath string `yaml:"publicKeyPath"`
}

type CookieSigning struct {
	Duration time.Duration `yaml:"duration"`
	Key      string        `yaml:"key"`
}

type OrganizationMemberAddingMode string

const (
	OrganizationMemberAddingModeDirect     OrganizationMemberAddingMode = "direct"
	OrganizationMemberAddingModeInvitation OrganizationMemberAddingMode = "invitation"
)

func (vt OrganizationMemberAddingMode) IsValid() bool {
	switch vt {
	case OrganizationMemberAddingModeDirect, OrganizationMemberAddingModeInvitation:
		return true
	}
	return false
}

var defaultConfig = func() *Config {
	return &Config{
		ID: "agola",
		Gateway: Gateway{
			TokenSigning: TokenSigning{
				Duration: 12 * time.Hour,
			},
			CookieSigning: CookieSigning{
				Duration: 12 * time.Hour,
			},
			OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
		},
		Runservice: Runservice{
			RunCacheExpireInterval:     7 * 24 * time.Hour,
			RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
			RunLogExpireInterval:       30 * 24 * time.Hour,
		},
		Executor: Executor{
			InitImage: InitImage{
				Image: "busybox:stable",
			},
			ActiveTasksLimit: 2,
		},
		Gitserver: Gitserver{
			RepositoryCleanupInterval:    24 * time.Hour,
			RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
		},
	}
}

func Parse(configFile string, componentsNames []string) (*Config, error) {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	c := defaultConfig()
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return nil, errors.WithStack(err)
	}

	// Use InternalServicesAPIToken for all internal services tokens without a value
	if c.RunserviceAPIToken == "" {
		c.RunserviceAPIToken = c.InternalServicesAPIToken
	}
	if c.ConfigstoreAPIToken == "" {
		c.ConfigstoreAPIToken = c.InternalServicesAPIToken
	}
	if c.ExecutorAPIToken == "" {
		c.ExecutorAPIToken = c.InternalServicesAPIToken
	}
	if c.GitserverAPIToken == "" {
		c.GitserverAPIToken = c.InternalServicesAPIToken
	}

	// Use global values if service values are empty
	if c.Gateway.APIExposedURL == "" {
		c.Gateway.APIExposedURL = c.APIExposedURL
	}
	if c.Gateway.WebExposedURL == "" {
		c.Gateway.WebExposedURL = c.WebExposedURL
	}
	if c.Gateway.RunserviceURL == "" {
		c.Gateway.RunserviceURL = c.RunserviceURL
	}
	if c.Gateway.RunserviceAPIToken == "" {
		c.Gateway.RunserviceAPIToken = c.RunserviceAPIToken
	}
	if c.Gateway.ConfigstoreURL == "" {
		c.Gateway.ConfigstoreURL = c.ConfigstoreURL
	}
	if c.Gateway.ConfigstoreAPIToken == "" {
		c.Gateway.ConfigstoreAPIToken = c.ConfigstoreAPIToken
	}
	if c.Gateway.GitserverURL == "" {
		c.Gateway.GitserverURL = c.GitserverURL
	}
	if c.Gateway.GitserverAPIToken == "" {
		c.Gateway.GitserverAPIToken = c.GitserverAPIToken
	}

	if c.Runservice.APIToken == "" {
		c.Runservice.APIToken = c.RunserviceAPIToken
	}
	if c.Runservice.ExecutorAPIToken == "" {
		c.Runservice.ExecutorAPIToken = c.ExecutorAPIToken
	}

	if c.Configstore.APIToken == "" {
		c.Configstore.APIToken = c.ConfigstoreAPIToken
	}

	if c.Scheduler.RunserviceURL == "" {
		c.Scheduler.RunserviceURL = c.RunserviceURL
	}
	if c.Scheduler.RunserviceAPIToken == "" {
		c.Scheduler.RunserviceAPIToken = c.RunserviceAPIToken
	}

	if c.Notification.WebExposedURL == "" {
		c.Notification.WebExposedURL = c.WebExposedURL
	}
	if c.Notification.RunserviceURL == "" {
		c.Notification.RunserviceURL = c.RunserviceURL
	}
	if c.Notification.RunserviceAPIToken == "" {
		c.Notification.RunserviceAPIToken = c.RunserviceAPIToken
	}
	if c.Notification.ConfigstoreURL == "" {
		c.Notification.ConfigstoreURL = c.ConfigstoreURL
	}
	if c.Notification.ConfigstoreAPIToken == "" {
		c.Notification.ConfigstoreAPIToken = c.ConfigstoreAPIToken
	}

	if c.Executor.APIToken == "" {
		c.Executor.APIToken = c.ExecutorAPIToken
	}
	if c.Executor.RunserviceURL == "" {
		c.Executor.RunserviceURL = c.RunserviceURL
	}
	if c.Executor.RunserviceAPIToken == "" {
		c.Executor.RunserviceAPIToken = c.RunserviceAPIToken
	}

	if c.Gitserver.APIToken == "" {
		c.Gitserver.APIToken = c.GitserverAPIToken
	}

	return c, Validate(c, componentsNames)
}

func validateCookieSigning(s *CookieSigning) error {
	if s.Key == "" {
		return errors.Errorf("empty cookie signing key")
	}

	return nil
}

func validateDB(db *DB) error {
	switch db.Type {
	case sql.Sqlite3:
	case sql.Postgres:
	default:
		if db.Type == "" {
			return errors.Errorf("type is not defined")
		}
		return errors.Errorf("unknown type %q", db.Type)
	}

	if db.ConnString == "" {
		return errors.Errorf("db connection string undefined")
	}

	return nil
}

func validateWeb(w *Web) error {
	if w.ListenAddress == "" {
		return errors.Errorf("listen address undefined")
	}

	if w.TLS {
		if w.TLSKeyFile == "" {
			return errors.Errorf("no tls key file specified")
		}
		if w.TLSCertFile == "" {
			return errors.Errorf("no tls cert file specified")
		}
	}

	return nil
}

func validateInitImage(i *InitImage) error {
	if i.Image == "" {
		return errors.Errorf("image is empty")
	}

	return nil
}

func Validate(c *Config, componentsNames []string) error {
	// Global
	if len(c.ID) > maxIDLength {
		return errors.Errorf("id too long")
	}
	if !util.ValidateName(c.ID) {
		return errors.Errorf("invalid id")
	}

	// Gateway
	if isComponentEnabled(componentsNames, "gateway") {
		if c.Gateway.APIExposedURL == "" {
			return errors.Errorf("gateway apiExposedURL is empty")
		}
		if c.Gateway.WebExposedURL == "" {
			return errors.Errorf("gateway webExposedURL is empty")
		}
		if c.Gateway.ConfigstoreURL == "" {
			return errors.Errorf("gateway configstoreURL is empty")
		}
		if c.Gateway.RunserviceURL == "" {
			return errors.Errorf("gateway runserviceURL is empty")
		}
		if err := validateCookieSigning(&c.Gateway.CookieSigning); err != nil {
			return errors.Wrap(err, "cookie signing configuration error")
		}
		if err := validateWeb(&c.Gateway.Web); err != nil {
			return errors.Wrapf(err, "gateway web configuration error")
		}
		if !c.Gateway.OrganizationMemberAddingMode.IsValid() {
			return errors.Errorf("gateway organizationMemberAddingMode is not valid")
		}
	}

	// Configstore
	if isComponentEnabled(componentsNames, "configstore") {
		if err := validateDB(&c.Runservice.DB); err != nil {
			return errors.Wrapf(err, "db configuration error")
		}
		if c.Configstore.DataDir == "" {
			return errors.Errorf("configstore dataDir is empty")
		}
		if err := validateWeb(&c.Configstore.Web); err != nil {
			return errors.Wrapf(err, "configstore web configuration error")
		}
	}

	// Runservice
	if isComponentEnabled(componentsNames, "runservice") {
		if err := validateDB(&c.Runservice.DB); err != nil {
			return errors.Wrapf(err, "db configuration error")
		}
		if c.Runservice.DataDir == "" {
			return errors.Errorf("runservice dataDir is empty")
		}
		if err := validateWeb(&c.Runservice.Web); err != nil {
			return errors.Wrapf(err, "runservice web configuration error")
		}
	}

	// Executor
	if isComponentEnabled(componentsNames, "executor") {
		if c.Executor.DataDir == "" {
			return errors.Errorf("executor dataDir is empty")
		}
		if c.Executor.ToolboxPath == "" {
			return errors.Errorf("git server toolboxPath is empty")
		}
		if c.Executor.RunserviceURL == "" {
			return errors.Errorf("executor runserviceURL is empty")
		}
		if c.Executor.Driver.Type == "" {
			return errors.Errorf("executor driver type is empty")
		}
		switch c.Executor.Driver.Type {
		case DriverTypeDocker:
		case DriverTypeK8s:
		default:
			return errors.Errorf("executor driver type %q unknown", c.Executor.Driver.Type)
		}

		if err := validateInitImage(&c.Executor.InitImage); err != nil {
			return errors.Wrapf(err, "executor initImage configuration error")
		}
	}

	// Scheduler
	if isComponentEnabled(componentsNames, "scheduler") {
		if c.Scheduler.RunserviceURL == "" {
			return errors.Errorf("scheduler runserviceURL is empty")
		}
	}

	// Notification
	if isComponentEnabled(componentsNames, "notification") {
		if c.Notification.WebExposedURL == "" {
			return errors.Errorf("notification webExposedURL is empty")
		}
		if c.Notification.ConfigstoreURL == "" {
			return errors.Errorf("notification configstoreURL is empty")
		}
		if c.Notification.RunserviceURL == "" {
			return errors.Errorf("notification runserviceURL is empty")
		}
	}

	// Git server
	if isComponentEnabled(componentsNames, "gitserver") {
		if c.Gitserver.DataDir == "" {
			return errors.Errorf("git server dataDir is empty")
		}
	}

	return nil
}

func isComponentEnabled(componentsNames []string, name string) bool {
	if util.StringInSlice(componentsNames, "all-base") && name != "executor" {
		return true
	}
	return util.StringInSlice(componentsNames, name)
}
