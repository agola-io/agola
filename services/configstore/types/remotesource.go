// Copyright 2022 Sorint.lab
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

package types

import (
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RemoteSourceType string

const (
	RemoteSourceTypeGitea  RemoteSourceType = "gitea"
	RemoteSourceTypeGithub RemoteSourceType = "github"
	RemoteSourceTypeGitlab RemoteSourceType = "gitlab"
)

type RemoteSourceAuthType string

const (
	RemoteSourceAuthTypePassword RemoteSourceAuthType = "password"
	RemoteSourceAuthTypeOauth2   RemoteSourceAuthType = "oauth2"
)

type RemoteSource struct {
	sqlg.ObjectMeta

	Name   string `json:"name,omitempty"`
	APIURL string `json:"apiurl,omitempty"`

	SkipVerify bool `json:"skip_verify,omitempty"`

	Type     RemoteSourceType     `json:"type,omitempty"`
	AuthType RemoteSourceAuthType `json:"auth_type,omitempty"`

	// Oauth2 data
	Oauth2ClientID     string `json:"client_id,omitempty"`
	Oauth2ClientSecret string `json:"client_secret,omitempty"`

	SSHHostKey string `json:"ssh_host_key,omitempty"` // Public ssh host key of the remote source

	SkipSSHHostKeyCheck bool `json:"skip_ssh_host_key_check,omitempty"`

	RegistrationEnabled bool `json:"registration_enabled,omitempty"`
	LoginEnabled        bool `json:"login_enabled,omitempty"`
}

func NewRemoteSource(tx *sql.Tx) *RemoteSource {
	return &RemoteSource{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}

func SourceSupportedAuthTypes(rsType RemoteSourceType) []RemoteSourceAuthType {
	switch rsType {
	case RemoteSourceTypeGitea:
		return []RemoteSourceAuthType{RemoteSourceAuthTypeOauth2, RemoteSourceAuthTypePassword}
	case RemoteSourceTypeGithub:
		fallthrough
	case RemoteSourceTypeGitlab:
		return []RemoteSourceAuthType{RemoteSourceAuthTypeOauth2}

	default:
		panic(errors.Errorf("unsupported remote source type: %q", rsType))
	}
}

func SourceSupportsAuthType(rsType RemoteSourceType, authType RemoteSourceAuthType) bool {
	supportedAuthTypes := SourceSupportedAuthTypes(rsType)
	for _, st := range supportedAuthTypes {
		if st == authType {
			return true
		}
	}
	return false
}
