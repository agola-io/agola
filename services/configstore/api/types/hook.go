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

type CreateHookRequest struct {
	ProjectRef string `json:"project_ref,omitempty"`

	DestinationURL string `json:"destination_url,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Secret string `json:"secret,omitempty"`

	PendingEvent *bool `json:"pending_event,omitempty"`

	SuccessEvent *bool `json:"success_event,omitempty"`

	ErrorEvent *bool `json:"error_event,omitempty"`

	FailedEvent *bool `json:"failed_event,omitempty"`
}

type UpdateHookRequest struct {
	DestinationURL string `json:"destination_url,omitempty"`

	ContentType string `json:"content_type,omitempty"`

	Secret string `json:"secret,omitempty"`

	PendingEvent *bool `json:"pending_event,omitempty"`

	SuccessEvent *bool `json:"success_event,omitempty"`

	ErrorEvent *bool `json:"error_event,omitempty"`

	FailedEvent *bool `json:"failed_event,omitempty"`
}
