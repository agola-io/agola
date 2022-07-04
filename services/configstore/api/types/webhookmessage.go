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

type CreateWebhookMessageRequest struct {
	IsCustom bool `json:"is_custom,omitempty"`

	ProjectID *string `json:"project_id,omitempty"`

	DestinationURL *string `json:"destination_url,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Secret string `json:"secret,omitempty"`

	TargetURL string `json:"target_url,omitempty"`

	CommitStatus string `json:"commit_status,omitempty"`

	Description string `json:"description,omitempty"`

	RepositoryPath string `json:"repository_path,omitempty"`

	CommitSha string `json:"commit_sha,omitempty"`

	StatusContext string `json:"status_context,omitempty"`
}
