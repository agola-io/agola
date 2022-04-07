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

const (
	SecretKind    = "secret"
	SecretVersion = "v0.1.0"
)

type Secret struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name string `json:"name,omitempty"`

	Parent Parent `json:"parent,omitempty"`

	Type SecretType `json:"type,omitempty"`

	// internal secret
	Data map[string]string `json:"data,omitempty"`

	// external secret
	SecretProviderID string `json:"secret_provider_id,omitempty"`
	Path             string `json:"path,omitempty"`
}

func NewSecret() *Secret {
	return &Secret{
		TypeMeta: stypes.TypeMeta{
			Kind:    SecretKind,
			Version: SecretVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
