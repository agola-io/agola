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
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Gateway             Gateway             `yaml:"gateway"`
	Scheduler           Scheduler           `yaml:"scheduler"`
	RunServiceScheduler RunServiceScheduler `yaml:"runServiceScheduler"`
	RunServiceExecutor  RunServiceExecutor  `yaml:"runServiceExecutor"`
	ConfigStore         ConfigStore         `yaml:"configStore"`
	GitServer           GitServer           `yaml:"gitServer"`
}

type Gateway struct {
	Debug bool `yaml:"debug"`

	// APIExposedURL is the gateway API exposed url i.e. https://myagola.example.com
	APIExposedURL string `yaml:"apiExposedURL"`

	// ExposedURL is the web interface exposed url i.e. https://myagola.example.com
	// This is used for generating the redirect_url in oauth2 redirects
	WebExposedURL string `yaml:"webExposedURL"`

	RunServiceURL  string `yaml:"runServiceURL"`
	ConfigStoreURL string `yaml:"configStoreURL"`
	GitServerURL   string `yaml:"gitServerURL"`

	Web  Web  `yaml:"web"`
	Etcd Etcd `yaml:"etcd"`
	LTS  LTS  `yaml:"lts"`

	TokenSigning TokenSigning `yaml:"tokenSigning"`

	AdminToken string `yaml:"adminToken"`
}

type Scheduler struct {
	Debug bool `yaml:"debug"`

	RunServiceURL string `yaml:"runServiceURL"`
}

type RunServiceScheduler struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`
	Web     Web    `yaml:"web"`
	Etcd    Etcd   `yaml:"etcd"`
	LTS     LTS    `yaml:"lts"`

	RunCacheExpireInterval time.Duration `yaml:"runCacheExpireInterval"`
}

type RunServiceExecutor struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	RunServiceURL string `yaml:"runServiceURL"`
	ToolboxPath   string `yaml:"toolboxPath"`

	Web Web `yaml:"web"`

	Driver Driver `yaml:"driver"`

	Labels map[string]string `yaml:"labels"`
	// ActiveTasksLimit is the max number of concurrent active tasks
	ActiveTasksLimit int `yaml:"active_tasks_limit"`
}

type ConfigStore struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	Web  Web  `yaml:"web"`
	Etcd Etcd `yaml:"etcd"`
	LTS  LTS  `yaml:"lts"`
}

type GitServer struct {
	Debug bool `yaml:"debug"`

	DataDir string `yaml:"dataDir"`

	GithookPath string `yaml:"githookPath"`
	GatewayURL  string `yaml:"gatewayURL"`

	Web  Web  `yaml:"web"`
	Etcd Etcd `yaml:"etcd"`
	LTS  LTS  `yaml:"lts"`
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

type LTSType string

const (
	LTSTypePosix LTSType = "posix"
	LTSTypeS3    LTSType = "s3"
)

type LTS struct {
	Type LTSType `yaml:"type"`

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

type Etcd struct {
	Endpoints string `yaml:"endpoints"`

	// TODO(sgotti) support encrypted private keys (add a private key password config entry)
	TLSCertFile   string `yaml:"tlsCertFile"`
	TLSKeyFile    string `yaml:"tlsKeyFile"`
	TLSCAFile     string `yaml:"tlsCAFile"`
	TLSSkipVerify bool   `yaml:"tlsSkipVerify"`
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

var defaultConfig = Config{
	Gateway: Gateway{
		TokenSigning: TokenSigning{
			Duration: 12 * time.Hour,
		},
	},
	RunServiceScheduler: RunServiceScheduler{
		RunCacheExpireInterval: 7 * 24 * time.Hour,
	},
	RunServiceExecutor: RunServiceExecutor{
		ActiveTasksLimit: 2,
	},
}

func Parse(configFile string) (*Config, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	c := &defaultConfig
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return nil, errors.WithStack(err)
	}

	return c, Validate(c)
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

func Validate(c *Config) error {
	// Gateway
	if c.Gateway.APIExposedURL == "" {
		return errors.Errorf("gateway apiExposedURL is empty")
	}
	if c.Gateway.WebExposedURL == "" {
		return errors.Errorf("gateway webExposedURL is empty")
	}
	if c.Gateway.ConfigStoreURL == "" {
		return errors.Errorf("gateway configStoreURL is empty")
	}
	if c.Gateway.RunServiceURL == "" {
		return errors.Errorf("gateway runServiceURL is empty")
	}
	if err := validateWeb(&c.Gateway.Web); err != nil {
		return errors.Wrapf(err, "gateway web configuration error")
	}

	// Configstore
	if c.ConfigStore.DataDir == "" {
		return errors.Errorf("configstore dataDir is empty")
	}
	if err := validateWeb(&c.ConfigStore.Web); err != nil {
		return errors.Wrapf(err, "configstore web configuration error")
	}

	// Runservice Scheduler
	if c.RunServiceScheduler.DataDir == "" {
		return errors.Errorf("runservice scheduler dataDir is empty")
	}
	if err := validateWeb(&c.RunServiceScheduler.Web); err != nil {
		return errors.Wrapf(err, "runservice scheduler web configuration error")
	}

	// Runservice Executor
	if c.RunServiceExecutor.DataDir == "" {
		return errors.Errorf("runservice executor dataDir is empty")
	}
	if c.RunServiceExecutor.ToolboxPath == "" {
		return errors.Errorf("git server toolboxPath is empty")
	}
	if c.RunServiceExecutor.RunServiceURL == "" {
		return errors.Errorf("runservice executor runServiceURL is empty")
	}
	if c.RunServiceExecutor.Driver.Type == "" {
		return errors.Errorf("runservice executor driver type is empty")
	}
	switch c.RunServiceExecutor.Driver.Type {
	case DriverTypeDocker:
	case DriverTypeK8s:
	default:
		return errors.Errorf("runservice executor driver type %q unknown", c.RunServiceExecutor.Driver.Type)
	}

	// Scheduler
	if c.Scheduler.RunServiceURL == "" {
		return errors.Errorf("scheduler runServiceURL is empty")
	}

	// Git server
	if c.GitServer.DataDir == "" {
		return errors.Errorf("git server dataDir is empty")
	}
	if c.GitServer.GithookPath == "" {
		return errors.Errorf("git server githookPath is empty")
	}
	if c.GitServer.GatewayURL == "" {
		return errors.Errorf("git server gatewayURL is empty")
	}

	return nil
}
