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

type CreateRemoteSourceRequest struct {
	Name                string `json:"name"`
	APIURL              string `json:"apiurl"`
	Type                string `json:"type"`
	AuthType            string `json:"auth_type"`
	SkipVerify          bool   `json:"skip_verify"`
	Oauth2ClientID      string `json:"oauth_2_client_id"`
	Oauth2ClientSecret  string `json:"oauth_2_client_secret"`
	SSHHostKey          string `json:"ssh_host_key"`
	SkipSSHHostKeyCheck bool   `json:"skip_ssh_host_key_check"`
	RegistrationEnabled *bool  `json:"registration_enabled"`
	LoginEnabled        *bool  `json:"login_enabled"`
}

type UpdateRemoteSourceRequest struct {
	Name                *string `json:"name"`
	APIURL              *string `json:"apiurl"`
	SkipVerify          *bool   `json:"skip_verify"`
	Oauth2ClientID      *string `json:"oauth_2_client_id"`
	Oauth2ClientSecret  *string `json:"oauth_2_client_secret"`
	SSHHostKey          *string `json:"ssh_host_key"`
	SkipSSHHostKeyCheck *bool   `json:"skip_ssh_host_key_check"`
	RegistrationEnabled *bool   `json:"registration_enabled"`
	LoginEnabled        *bool   `json:"login_enabled"`
}

type RemoteSourceResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	AuthType            string `json:"auth_type"`
	RegistrationEnabled bool   `json:"registration_enabled"`
	LoginEnabled        bool   `json:"login_enabled"`
}
