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

type CreateProjectRequest struct {
	Name                string     `json:"name,omitempty"`
	ParentRef           string     `json:"parent_ref,omitempty"`
	Visibility          Visibility `json:"visibility,omitempty"`
	RepoPath            string     `json:"repo_path,omitempty"`
	RemoteSourceName    string     `json:"remote_source_name,omitempty"`
	SkipSSHHostKeyCheck bool       `json:"skip_ssh_host_key_check,omitempty"`
	PassVarsToForkedPR  bool       `json:"pass_vars_to_forked_pr,omitempty"`
}

type UpdateProjectRequest struct {
	Name               *string     `json:"name,omitempty"`
	ParentRef          *string     `json:"parent_ref,omitempty"`
	Visibility         *Visibility `json:"visibility,omitempty"`
	PassVarsToForkedPR *bool       `json:"pass_vars_to_forked_pr,omitempty"`
}

type ProjectResponse struct {
	ID                 string     `json:"id,omitempty"`
	Name               string     `json:"name,omitempty"`
	Path               string     `json:"path,omitempty"`
	ParentPath         string     `json:"parent_path,omitempty"`
	Visibility         Visibility `json:"visibility,omitempty"`
	GlobalVisibility   string     `json:"global_visibility,omitempty"`
	PassVarsToForkedPR bool       `json:"pass_vars_to_forked_pr,omitempty"`
}

type ProjectCreateRunRequest struct {
	Branch    string `json:"branch,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
}
