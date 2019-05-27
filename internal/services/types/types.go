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

package types

import (
	"fmt"
	"regexp"
	"time"
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

	RemoteUserID   string `json:"remote_user_id,omitempty"`
	RemoteUserName string `json:"remote_username,omitempty"`

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

	When *When `json:"when,omitempty"`
}

type When struct {
	Branch *WhenConditions `json:"branch,omitempty"`
	Tag    *WhenConditions `json:"tag,omitempty"`
	Ref    *WhenConditions `json:"ref,omitempty"`
}

type WhenConditions struct {
	Include []WhenCondition `json:"include,omitempty"`
	Exclude []WhenCondition `json:"exclude,omitempty"`
}

type WhenConditionType int

const (
	WhenConditionTypeSimple WhenConditionType = iota
	WhenConditionTypeRegExp
)

type WhenCondition struct {
	Type  WhenConditionType `json:"type,omitempty"`
	Match string            `json:"match,omitempty"`
}

func MatchWhen(when *When, branch, tag, ref string) bool {
	include := true
	if when != nil {
		include = false
		// test only if branch is not empty, if empty mean that we are not in a branch
		if when.Branch != nil && branch != "" {
			// first check includes and override with excludes
			if matchCondition(when.Branch.Include, branch) {
				include = true
			}
			if matchCondition(when.Branch.Exclude, branch) {
				include = false
			}
		}
		// test only if tag is not empty, if empty mean that we are not in a tag
		if when.Tag != nil && tag != "" {
			// first check includes and override with excludes
			if matchCondition(when.Tag.Include, tag) {
				include = true
			}
			if matchCondition(when.Tag.Exclude, tag) {
				include = false
			}
		}
		// we assume that ref always have a value
		if when.Ref != nil {
			// first check includes and override with excludes
			if matchCondition(when.Ref.Include, ref) {
				include = true
			}
			if matchCondition(when.Ref.Exclude, ref) {
				include = false
			}
		}
	}

	return include
}

func matchCondition(conds []WhenCondition, s string) bool {
	for _, cond := range conds {
		switch cond.Type {
		case WhenConditionTypeSimple:
			if cond.Match == s {
				return true
			}
		case WhenConditionTypeRegExp:
			re, err := regexp.Compile(cond.Match)
			if err != nil {
				panic(err)
			}
			if re.MatchString(s) {
				return true
			}
		}
	}
	return false
}
