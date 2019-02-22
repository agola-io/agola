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
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/sorintlab/agola/internal/util"
)

const (
	emptySHA = "0000000000000000000000000000000000000000"
)

type Hook struct {
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
		Owner    struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"owner"`
	} `json:"repository"`

	Commits []Commit `json:"commits"`

	Sender struct {
		ID       int64  `json:"id"`
		Login    string `json:"login"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar_url"`
	} `json:"sender"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	URL     string `json:"url"`
}

func isBareRepository(path string) (bool, error) {
	git := &util.Git{}
	out, err := git.Output(context.Background(), nil, "rev-parse", "--is-bare-repository")
	if err != nil {
		return false, err
	}
	return string(out) == "true", nil
}

func commitMessage(sha string) (string, error) {
	git := &util.Git{}
	out, err := git.Output(context.Background(), nil, "show", "-s", "--format=%B", sha)
	return strings.TrimSpace(string(out)), err
}

func genHook(oldCommit, newCommit, ref string) (*Hook, error) {
	hook := &Hook{}

	hook.Before = oldCommit
	hook.After = newCommit
	hook.Ref = ref

	hook.Commits = make([]Commit, 2)

	hook.Commits[0].ID = newCommit
	hook.Commits[1].ID = oldCommit

	newCommitMessage, err := commitMessage(newCommit)
	if err != nil {
		return nil, err
	}
	hook.Commits[0].Message = newCommitMessage
	if oldCommit != emptySHA {
		oldCommitMessage, err := commitMessage(oldCommit)
		if err != nil {
			return nil, err
		}
		hook.Commits[1].Message = oldCommitMessage
	}

	git := &util.Git{}
	repo, _ := git.ConfigGet(context.Background(), "agola.repo")
	log.Printf("repo: %s", repo)
	parts := strings.Split(string(repo), "/")

	hook.Repo.Owner.Username = parts[0]
	hook.Repo.Name = parts[1]

	return hook, nil
}

func main() {
	log.Printf("post receice hook")

	//data, _ := ioutil.ReadAll(os.Stdin)
	//parts := strings.Split(string(data), " ")
	//if len(parts) != 3 {
	//	log.Fatalf("not enought parts. data: %s", data)
	//}

	//oldCommit := parts[0]
	//newCommit := parts[1]
	//ref := parts[2]

	oldCommit := os.Args[1]
	newCommit := os.Args[2]
	ref := os.Args[3]

	log.Printf("oldcommit: %s, newcommit: %s, ref: %s", oldCommit, newCommit, ref)

	git := &util.Git{}
	repo, _ := git.ConfigGet(context.Background(), "agola.repo")
	webhookURL, _ := git.ConfigGet(context.Background(), "agola.webhookURL")
	log.Printf("repo: %s", repo)
	log.Printf("webhookURL: %s", webhookURL)

	hook, _ := genHook(oldCommit, newCommit, ref)
	hookj, _ := json.Marshal(hook)

	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(hookj))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitea-Event", "push")
	if _, err := http.DefaultClient.Do(req); err != nil {
		log.Fatalf("err: %v", err)
	}
}
