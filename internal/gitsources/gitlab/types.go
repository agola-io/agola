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

package gitlab

// TODO(sgotti) generated with https://github.com/mholt/json-to-go and manually
// cleaned. Many fields are not needed, remove them.

type pushHook struct {
	ObjectKind   string `json:"object_kind"`
	EventName    string `json:"event_name"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Ref          string `json:"ref"`
	CheckoutSha  string `json:"checkout_sha"`
	Message      string `json:"message"`
	UserID       int    `json:"user_id"`
	UserName     string `json:"user_name"`
	UserUsername string `json:"user_username"`
	UserEmail    string `json:"user_email"`
	UserAvatar   string `json:"user_avatar"`
	Project      struct {
		ID                int    `json:"id"`
		Name              string `json:"name"`
		Description       string `json:"description"`
		WebURL            string `json:"web_url"`
		GitSSHURL         string `json:"git_ssh_url"`
		GitHTTPURL        string `json:"git_http_url"`
		Namespace         string `json:"namespace"`
		VisibilityLevel   int    `json:"visibility_level"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
		URL               string `json:"url"`
		SSHURL            string `json:"ssh_url"`
		HTTPURL           string `json:"http_url"`
	} `json:"project"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Modified []string `json:"modified"`
	} `json:"commits"`
	TotalCommitsCount int `json:"total_commits_count"`
	Repository        struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Description     string `json:"description"`
		Homepage        string `json:"homepage"`
		GitHTTPURL      string `json:"git_http_url"`
		GitSSHURL       string `json:"git_ssh_url"`
		VisibilityLevel int    `json:"visibility_level"`
	} `json:"repository"`
}

type pullRequestHook struct {
	ObjectKind string `json:"object_kind"`
	EventType  string `json:"event_type"`
	User       struct {
		Name      string `json:"name"`
		Username  string `json:"username"`
		AvatarURL string `json:"avatar_url"`
	} `json:"user"`
	Project struct {
		ID                int    `json:"id"`
		Name              string `json:"name"`
		Description       string `json:"description"`
		WebURL            string `json:"web_url"`
		GitSSHURL         string `json:"git_ssh_url"`
		GitHTTPURL        string `json:"git_http_url"`
		Namespace         string `json:"namespace"`
		VisibilityLevel   int    `json:"visibility_level"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
		Homepage          string `json:"homepage"`
		URL               string `json:"url"`
		SSHURL            string `json:"ssh_url"`
		HTTPURL           string `json:"http_url"`
	} `json:"project"`
	ObjectAttributes struct {
		AuthorID                  int    `json:"author_id"`
		Description               string `json:"description"`
		HeadPipelineID            int    `json:"head_pipeline_id"`
		ID                        int    `json:"id"`
		Iid                       int    `json:"iid"`
		MergeStatus               string `json:"merge_status"`
		MergeWhenPipelineSucceeds bool   `json:"merge_when_pipeline_succeeds"`
		SourceBranch              string `json:"source_branch"`
		SourceProjectID           int    `json:"source_project_id"`
		State                     string `json:"state"`
		TargetBranch              string `json:"target_branch"`
		TargetProjectID           int    `json:"target_project_id"`
		Title                     string `json:"title"`
		URL                       string `json:"url"`
		Source                    struct {
			ID                int    `json:"id"`
			Name              string `json:"name"`
			Description       string `json:"description"`
			WebURL            string `json:"web_url"`
			GitSSHURL         string `json:"git_ssh_url"`
			GitHTTPURL        string `json:"git_http_url"`
			Namespace         string `json:"namespace"`
			VisibilityLevel   int    `json:"visibility_level"`
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
			Homepage          string `json:"homepage"`
			URL               string `json:"url"`
			SSHURL            string `json:"ssh_url"`
			HTTPURL           string `json:"http_url"`
		} `json:"source"`
		Target struct {
			ID                int    `json:"id"`
			Name              string `json:"name"`
			Description       string `json:"description"`
			WebURL            string `json:"web_url"`
			GitSSHURL         string `json:"git_ssh_url"`
			GitHTTPURL        string `json:"git_http_url"`
			Namespace         string `json:"namespace"`
			VisibilityLevel   int    `json:"visibility_level"`
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
			Homepage          string `json:"homepage"`
			URL               string `json:"url"`
			SSHURL            string `json:"ssh_url"`
			HTTPURL           string `json:"http_url"`
		} `json:"target"`
		LastCommit struct {
			ID      string `json:"id"`
			Message string `json:"message"`
			URL     string `json:"url"`
			Author  struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"author"`
		} `json:"last_commit"`
		WorkInProgress bool `json:"work_in_progress"`
		TotalTimeSpent int  `json:"total_time_spent"`
	} `json:"object_attributes"`
	Changes struct {
		TotalTimeSpent struct {
			Current int `json:"current"`
		} `json:"total_time_spent"`
	} `json:"changes"`
	Repository struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Description string `json:"description"`
		Homepage    string `json:"homepage"`
	} `json:"repository"`
}
