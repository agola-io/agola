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

package gitea

type pushHook struct {
	Sha     string `json:"sha"`
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Compare string `json:"compare_url"`
	RefType string `json:"ref_type"`

	Pusher struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Login    string `json:"login"`
		Username string `json:"username"`
	} `json:"pusher"`

	Repo struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		URL      string `json:"html_url"`
		Private  bool   `json:"private"`
		SSHURL   string `json:"ssh_url"`
		Owner    struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"owner"`
	} `json:"repository"`

	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
	} `json:"commits"`

	Sender struct {
		ID       int64  `json:"id"`
		Login    string `json:"login"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar_url"`
	} `json:"sender"`
}

type pullRequestHook struct {
	Action      string `json:"action"`
	Number      int64  `json:"number"`
	PullRequest struct {
		ID   int64 `json:"id"`
		User struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Name     string `json:"full_name"`
			Email    string `json:"email"`
			Avatar   string `json:"avatar_url"`
		} `json:"user"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		State     string `json:"state"`
		URL       string `json:"html_url"`
		Mergeable bool   `json:"mergeable"`
		Merged    bool   `json:"merged"`
		MergeBase string `json:"merge_base"`
		Base      struct {
			Label string `json:"label"`
			Ref   string `json:"ref"`
			Sha   string `json:"sha"`
			Repo  struct {
				ID       int64  `json:"id"`
				Name     string `json:"name"`
				FullName string `json:"full_name"`
				URL      string `json:"html_url"`
				Private  bool   `json:"private"`
				SSHURL   string `json:"ssh_url"`
				Owner    struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Name     string `json:"full_name"`
					Email    string `json:"email"`
					Avatar   string `json:"avatar_url"`
				} `json:"owner"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			Label string `json:"label"`
			Ref   string `json:"ref"`
			Sha   string `json:"sha"`
			Repo  struct {
				ID       int64  `json:"id"`
				Name     string `json:"name"`
				FullName string `json:"full_name"`
				URL      string `json:"html_url"`
				Private  bool   `json:"private"`
				SSHURL   string `json:"ssh_url"`
				Owner    struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Name     string `json:"full_name"`
					Email    string `json:"email"`
					Avatar   string `json:"avatar_url"`
				} `json:"owner"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
	Repo struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		URL      string `json:"html_url"`
		Private  bool   `json:"private"`
		SSHURL   string `json:"ssh_url"`
		Owner    struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Name     string `json:"full_name"`
			Email    string `json:"email"`
			Avatar   string `json:"avatar_url"`
		} `json:"owner"`
	} `json:"repository"`
	Sender struct {
		ID       int64  `json:"id"`
		Login    string `json:"login"`
		Username string `json:"username"`
		Name     string `json:"full_name"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar_url"`
	} `json:"sender"`
}
