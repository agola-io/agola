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

package gitserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gotest.tools/assert"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
)

const (
	branchName = "master"
	tagName    = "v1.0"
)

func createTag(t *testing.T, ctx context.Context, git *util.Git, committerTime time.Time) {
	_, err := git.Output(ctx, nil, "branch", "test")
	testutil.NilError(t, err)

	_, err = git.Output(ctx, nil, "checkout", "test")
	testutil.NilError(t, err)

	git.Env = append(git.Env, "GIT_COMMITTER_DATE="+committerTime.Format(time.RFC3339))
	_, err = git.Output(ctx, nil, "commit", "--allow-empty", "-m", "root commit")
	testutil.NilError(t, err)

	_, err = git.Output(ctx, nil, "tag", tagName, "-m", "tag test")
	testutil.NilError(t, err)
}

func createBranch(t *testing.T, ctx context.Context, git *util.Git, committerTime time.Time) {
	git.Env = append(git.Env, "GIT_COMMITTER_DATE="+committerTime.Format(time.RFC3339))
	_, err := git.Output(ctx, nil, "commit", "--allow-empty", "-m", "'root commit'")
	testutil.NilError(t, err)
}

func TestRepoCleaner(t *testing.T) {
	tests := []struct {
		name          string
		branchOldTime bool
		tagOldTime    bool
	}{
		{
			name:          "test delete branch",
			branchOldTime: true,
			tagOldTime:    false,
		},
		{
			name:          "test delete tag",
			branchOldTime: false,
			tagOldTime:    true,
		},
		{
			name:          "test delete repository dir",
			branchOldTime: true,
			tagOldTime:    true,
		},
	}

	oldCommitterTime := time.Date(2015, time.January, 15, 1, 1, 1, 1, time.UTC)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := testutil.NewLogger(t)
			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			gitDataDir := filepath.Join(dir, "gitserver")

			config := &config.Gitserver{
				DataDir:                      gitDataDir,
				RepositoryCleanupInterval:    10 * time.Second,
				RepositoryRefsExpireInterval: 24 * time.Hour,
			}

			gs, err := NewGitserver(ctx, log, config)
			testutil.NilError(t, err)

			userDirRepo := filepath.Join(gitDataDir, "user01", "repo01")
			err = os.MkdirAll(userDirRepo, os.ModePerm)
			testutil.NilError(t, err)

			git := &util.Git{GitDir: userDirRepo}
			_, err = git.Output(ctx, nil, "init")
			testutil.NilError(t, err)

			_, err = git.Output(ctx, nil, "config", "--unset", "core.bare")
			testutil.NilError(t, err)

			_, err = git.Output(ctx, nil, "config", "user.email", "user01@example.com")
			testutil.NilError(t, err)

			_, err = git.Output(ctx, nil, "config", "user.name", "user01")
			testutil.NilError(t, err)

			var committerTime time.Time
			if tt.branchOldTime {
				committerTime = oldCommitterTime
			} else {
				committerTime = time.Now()
			}
			createBranch(t, ctx, git, committerTime)

			if tt.tagOldTime {
				committerTime = oldCommitterTime
			} else {
				committerTime = time.Now()
			}
			createTag(t, ctx, git, committerTime)
			_, err = git.Output(ctx, nil, "config", "--bool", "core.bare", "true")
			testutil.NilError(t, err)

			err = gs.scanRepos(ctx)
			testutil.NilError(t, err)

			if tt.branchOldTime && tt.tagOldTime {
				_, err = os.Open(userDirRepo)
				assert.ErrorType(t, err, os.IsNotExist)

				return
			}

			branches, err := gs.getBranches(git, ctx)
			testutil.NilError(t, err)

			found := false
			for _, b := range branches {
				if b == branchName {
					found = true
					break
				}
			}
			assert.Assert(t, !tt.branchOldTime || !found, "expected branch %s deleted", branchName)
			assert.Assert(t, tt.branchOldTime || found, "expected branch %s", branchName)

			tags, err := gs.getTags(git, ctx)
			testutil.NilError(t, err)

			found = false
			for _, b := range tags {
				if b == tagName {
					found = true
					break
				}
			}
			assert.Assert(t, !tt.tagOldTime || !found, "expected tag %s deleted", tagName)
			assert.Assert(t, tt.tagOldTime || found, "expected tag %s", tagName)
		})
	}
}
