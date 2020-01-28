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

package types

import (
	"encoding/json"
	"fmt"
	"time"

	"agola.io/agola/services/types"
	"agola.io/agola/util"
)

// Configstore types

type ConfigType string

const (
	ConfigTypeUser         ConfigType = "user"
	ConfigTypeOrg          ConfigType = "org"
	ConfigTypeOrgMember    ConfigType = "orgmember"
	ConfigTypeProjectGroup ConfigType = "projectgroup"
	ConfigTypeProject      ConfigType = "project"
	ConfigTypeRemoteSource ConfigType = "remotesource"
	ConfigTypeSecret       ConfigType = "secret"
	ConfigTypeVariable     ConfigType = "variable"
)

type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibilityPrivate Visibility = "private"
)

func IsValidVisibility(v Visibility) bool {
	switch v {
	case VisibilityPublic:
	case VisibilityPrivate:
	default:
		return false
	}
	return true
}

type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleMember MemberRole = "member"
)

func IsValidMemberRole(r MemberRole) bool {
	switch r {
	case MemberRoleOwner:
	case MemberRoleMember:
	default:
		return false
	}
	return true
}

type Parent struct {
	Type ConfigType `json:"type,omitempty"`
	ID   string     `json:"id,omitempty"`
}

type User struct {
	// The type version. Increase when a breaking change is done. Usually not
	// needed when adding fields.
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

	Name string `json:"name,omitempty"`

	// Secret is a secret that could be used for signing or other purposes. It
	// should never be directly exposed to external services
	Secret string `json:"secret,omitempty"`

	LinkedAccounts map[string]*LinkedAccount `json:"linked_accounts,omitempty"`

	// Optional local auth
	Password string `json:"password,omitempty"`

	Tokens map[string]string `json:"tokens,omitempty"`

	// Admin defines if the user is a global admin
	Admin bool `json:"admin,omitempty"`
}

type Organization struct {
	// The type version. Increase when a breaking change is done. Usually not
	// needed when adding fields.
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

	Name string `json:"name,omitempty"`

	Visibility Visibility `json:"visibility,omitempty"`

	// CreatorUserID is the user id that created the organization. It could be empty
	// if the org was created by using the admin user or the user has been removed.
	CreatorUserID string    `json:"creator_user_id,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type OrganizationMember struct {
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

	OrganizationID string `json:"organization_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`

	MemberRole MemberRole `json:"member_role,omitempty"`
}

type ProjectGroup struct {
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Visibility Visibility `json:"visibility,omitempty"`
}

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
	// The type version. Increase when a breaking change is done. Usually not
	// needed when adding fields.
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

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

func (rs *RemoteSource) UnmarshalJSON(b []byte) error {
	type remoteSource RemoteSource

	trs := (*remoteSource)(rs)

	if err := json.Unmarshal(b, &trs); err != nil {
		return err
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
		panic(fmt.Errorf("unsupported remote source type: %q", rsType))
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

type LinkedAccount struct {
	// The type version. Increase when a breaking change is done. Usually not
	// needed when adding fields.
	Version string `json:"version,omitempty"`

	ID string `json:"id,omitempty"`

	RemoteUserID        string `json:"remote_user_id,omitempty"`
	RemoteUserName      string `json:"remote_username,omitempty"`
	RemoteUserAvatarURL string `json:"remote_user_avatar_url,omitempty"`

	RemoteSourceID string `json:"remote_source_id,omitempty"`

	UserAccessToken string `json:"user_access_token,omitempty"`

	Oauth2AccessToken          string    `json:"oauth2_access_token,omitempty"`
	Oauth2RefreshToken         string    `json:"oauth2_refresh_token,omitempty"`
	Oauth2AccessTokenExpiresAt time.Time `json:"oauth_2_access_token_expires_at,omitempty"`
}

// RemoteRepositoryConfigType defines how a remote repository is configured and
// managed. Currently only "remotesource" is supported.
// In future other config types (like a fully manual config) could be supported.
type RemoteRepositoryConfigType string

const (
	// RemoteRepositoryConfigTypeManual is currently only used for tests and not available for direct usage
	RemoteRepositoryConfigTypeManual       RemoteRepositoryConfigType = "manual"
	RemoteRepositoryConfigTypeRemoteSource RemoteRepositoryConfigType = "remotesource"
)

func IsValidRemoteRepositoryConfigType(t RemoteRepositoryConfigType) bool {
	switch t {
	case RemoteRepositoryConfigTypeManual:
	case RemoteRepositoryConfigTypeRemoteSource:
	default:
		return false
	}
	return true
}

type Project struct {
	// The type version. Increase when a breaking change is done. Usually not
	// needed when adding fields.
	Version string `json:"version,omitempty"`

	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	// Secret is a secret that could be used for signing or other purposes. It
	// should never be directly exposed to external services
	Secret string `json:"secret,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Visibility Visibility `json:"visibility,omitempty"`

	// Remote Repository fields
	RemoteRepositoryConfigType RemoteRepositoryConfigType `json:"remote_repository_config_type,omitempty"`

	RemoteSourceID  string `json:"remote_source_id,omitempty"`
	LinkedAccountID string `json:"linked_account_id,omitempty"`

	// The remote repository id
	RepositoryID string `json:"repository_id,omitempty"`

	// The remote repository path. It may be different for every kind of git source.
	// NOTE: it may be changed remotely but won't be updated here. Every git source
	// works differently so we must find a way to update it:
	// * let the user update it manually
	// * auto update it if the remote let us query by repository id (gitea cannot
	// do this but gitlab can and github has an hidden api to do this)
	RepositoryPath string `json:"repository_path,omitempty"`

	SSHPrivateKey string `json:"ssh_private_key,omitempty"` // PEM Encoded private key

	SkipSSHHostKeyCheck bool `json:"skip_ssh_host_key_check,omitempty"`

	// Webhooksecret is the secret passed to git sources that support a
	// secret/token for signing or verifying the webhook payload
	WebhookSecret string `json:"webhook_secret,omitempty"`

	PassVarsToForkedPR bool `json:"pass_vars_to_forked_pr,omitempty"`
}

type SecretType string

const (
	SecretTypeInternal SecretType = "internal"
	SecretTypeExternal SecretType = "external"
)

type SecretProviderType string

const (
	// TODO(sgotti) unimplemented
	SecretProviderK8s   SecretProviderType = "k8s"
	SecretProviderVault SecretProviderType = "vault"
)

type Secret struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Type SecretType `json:"type,omitempty"`

	// internal secret
	Data map[string]string `json:"data,omitempty"`

	// external secret
	SecretProviderID string `json:"secret_provider_id,omitempty"`
	Path             string `json:"path,omitempty"`
}

type Variable struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Values []VariableValue `json:"values,omitempty"`
}

type VariableValue struct {
	SecretName string `json:"secret_name,omitempty"`
	SecretVar  string `json:"secret_var,omitempty"`

	When *types.When `json:"when,omitempty"`
}
