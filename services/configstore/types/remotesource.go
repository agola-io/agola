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
	"encoding/json"

	"agola.io/agola/internal/errors"
	stypes "agola.io/agola/services/types"
	"agola.io/agola/util"

	"github.com/gofrs/uuid"
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

const (
	RemoteSourceKind    = "remotesource"
	RemoteSourceVersion = "v0.1.0"
)

type RemoteSource struct {
	stypes.TypeMeta
	stypes.ObjectMeta

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

	RegistrationEnabled *bool `json:"registration_enabled,omitempty"`
	LoginEnabled        *bool `json:"login_enabled,omitempty"`
}

func NewRemoteSource() *RemoteSource {
	return &RemoteSource{
		TypeMeta: stypes.TypeMeta{
			Kind:    RemoteSourceKind,
			Version: RemoteSourceVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}

func (rs *RemoteSource) UnmarshalJSON(b []byte) error {
	type remoteSource RemoteSource

	trs := (*remoteSource)(rs)

	if err := json.Unmarshal(b, &trs); err != nil {
		return errors.WithStack(err)
	}

	if trs.RegistrationEnabled == nil {
		trs.RegistrationEnabled = util.BoolP(true)
	}
	if trs.LoginEnabled == nil {
		trs.LoginEnabled = util.BoolP(true)
	}

	return nil
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
