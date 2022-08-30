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

package gitsave

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"
)

const (
	gitIndexFile      = "index"
	defaultRefsPrefix = "refs/gitsave"
)

func copyFile(src, dest string) error {
	srcf, err := os.Open(src)
	if err != nil {
		return errors.WithStack(err)
	}
	defer srcf.Close()

	destf, err := os.Create(dest)
	if err != nil {
		return errors.WithStack(err)
	}
	defer destf.Close()

	_, err = io.Copy(destf, srcf)
	return errors.WithStack(err)
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, errors.WithStack(err)
	}
	return !errors.Is(err, os.ErrNotExist), nil
}

// GitDir returns the git dir relative to the working dir
func GitDir() (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "rev-parse", "--git-dir")
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], errors.WithStack(err)
}

func currentGitBranch() (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], errors.WithStack(err)
}

// gitDir returns the git dir relative to the working dir
func gitWriteTree(indexPath string) (string, error) {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	lines, err := git.OutputLines(context.Background(), nil, "write-tree")
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected  one line", len(lines))
	}
	return lines[0], errors.WithStack(err)
}

func gitCommitTree(message, treeSHA string) (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "commit-tree", "-m", message, treeSHA)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], errors.WithStack(err)
}

func gitUpdateRef(message, ref, commitSHA string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "update-ref", "-m", message, ref, commitSHA)
	return errors.WithStack(err)
}

func gitUpdateFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", "-u")
	return errors.WithStack(err)
}

func gitAddUntrackedFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", ".")
	return errors.WithStack(err)
}

func gitAddIgnoredFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", "-f", "-A", ".")
	return errors.WithStack(err)
}

func GitAddRemote(configPath, name, url string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "remote", "add", name, url)
	return errors.WithStack(err)
}

func GitPush(configPath, remote, branch string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "push", remote, branch, "-f")
	return errors.WithStack(err)
}

type GitSaveConfig struct {
	AddUntracked bool
	AddIgnored   bool
	RefsPrefix   string
}

type GitSave struct {
	log        zerolog.Logger
	conf       *GitSaveConfig
	refsPrefix string
}

func NewGitSave(log zerolog.Logger, conf *GitSaveConfig) *GitSave {
	refsPrefix := conf.RefsPrefix
	if refsPrefix == "" {
		refsPrefix = defaultRefsPrefix
	}
	return &GitSave{
		log:        log,
		conf:       conf,
		refsPrefix: refsPrefix,
	}

}

func (s *GitSave) RefsPrefix() string {
	return s.refsPrefix
}

// Save adds files to the provided index, creates a tree and a commit pointing to
// that tree, finally it creates a branch poiting to that commit
// Save will use the current worktree index if available to speed the index generation
func (s *GitSave) Save(message, branchName string) (string, error) {
	gitdir, err := GitDir()
	if err != nil {
		return "", errors.WithStack(err)
	}

	tmpIndexPath := filepath.Join(gitdir, "gitsave-index-"+uuid.Must(uuid.NewV4()).String())
	defer os.Remove(tmpIndexPath)

	indexPath := filepath.Join(gitdir, gitIndexFile)

	curBranch, err := currentGitBranch()
	if err != nil {
		return "", errors.WithStack(err)
	}

	indexExists, err := fileExists(indexPath)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if indexExists {
		// copy current git index to a temporary index
		if err := copyFile(indexPath, tmpIndexPath); err != nil {
			return "", errors.WithStack(err)
		}
		s.log.Info().Msgf("created temporary index: %s", tmpIndexPath)
		// read the current branch tree information into the index
		git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + tmpIndexPath}}
		_, err = git.Output(context.Background(), nil, "read-tree", curBranch)
		if err != nil {
			return "", errors.WithStack(err)
		}
	} else {
		s.log.Info().Msgf("index %s does not exist", indexPath)
	}

	s.log.Info().Msgf("updating files already in the index")
	if err := gitUpdateFiles(tmpIndexPath); err != nil {
		return "", errors.WithStack(err)
	}

	if s.conf.AddUntracked {
		s.log.Info().Msgf("adding untracked files")
		if err := gitAddUntrackedFiles(tmpIndexPath); err != nil {
			return "", errors.WithStack(err)
		}
	}

	if s.conf.AddIgnored {
		s.log.Info().Msgf("adding ignored files")
		if err := gitAddIgnoredFiles(tmpIndexPath); err != nil {
			return "", errors.WithStack(err)
		}
	}

	s.log.Info().Msgf("writing tree file")
	treeSHA, err := gitWriteTree(tmpIndexPath)
	if err != nil {
		return "", errors.WithStack(err)
	}
	s.log.Info().Msgf("tree: %s", treeSHA)

	s.log.Info().Msgf("committing tree")
	commitSHA, err := gitCommitTree(message, treeSHA)
	if err != nil {
		return "", errors.WithStack(err)
	}
	s.log.Info().Msgf("commit: %s", commitSHA)

	s.log.Info().Msgf("updating ref")
	if err = gitUpdateRef("git-save", filepath.Join(s.refsPrefix, branchName), commitSHA); err != nil {
		return "", errors.WithStack(err)
	}

	return commitSHA, nil
}
