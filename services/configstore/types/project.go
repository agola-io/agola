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
	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
)

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

const (
	ProjectKind    = "project"
	ProjectVersion = "v0.1.0"
)

type Project struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	// Secret is a secret that could be used for signing or other purposes. It
	// should never be directly exposed to external services
	Secret string `json:"secret,omitempty"`

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

func NewProject() *Project {
	return &Project{
		TypeMeta: stypes.TypeMeta{
			Kind:    ProjectKind,
			Version: ProjectVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
