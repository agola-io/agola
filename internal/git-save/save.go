package gitsave

import (
	"context"
	"io"
	"os"
	"path/filepath"

	uuid "github.com/satori/go.uuid"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
	"go.uber.org/zap"
)

const (
	gitIndexFile  = "index"
	gitRefsPrefix = "refs/gitsave"
)

func copyFile(src, dest string) error {
	srcf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcf.Close()

	destf, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destf.Close()

	_, err = io.Copy(destf, srcf)
	return err
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return !os.IsNotExist(err), nil
}

// GitDir returns the git dir relative to the working dir
func GitDir() (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "rev-parse", "--git-dir")
	if err != nil {
		return "", err
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], err
}

func currentGitBranch() (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return "", err
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], err
}

// gitDir returns the git dir relative to the working dir
func gitWriteTree(indexPath string) (string, error) {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	lines, err := git.OutputLines(context.Background(), nil, "write-tree")
	if err != nil {
		return "", err
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected  one line", len(lines))
	}
	return lines[0], err
}

func gitCommitTree(message, treeSHA string) (string, error) {
	git := &util.Git{}
	lines, err := git.OutputLines(context.Background(), nil, "commit-tree", "-m", message, treeSHA)
	if err != nil {
		return "", err
	}
	if len(lines) != 1 {
		return "", errors.Errorf("received %d lines, expected one line", len(lines))
	}
	return lines[0], err
}

func gitUpdateRef(message, ref, commitSHA string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "update-ref", "-m", message, ref, commitSHA)
	return err
}

func gitUpdateFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", "-u")
	return err
}

func gitAddUntrackedFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", ".")
	return err
}

func gitAddIgnoredFiles(indexPath string) error {
	git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + indexPath}}
	_, err := git.Output(context.Background(), nil, "add", "-f", "-A", ".")
	return err
}

func GitAddRemote(configPath, name, url string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "remote", "add", name, url)
	return err
}

func GitPush(configPath, remote, branch string) error {
	git := &util.Git{}
	_, err := git.Output(context.Background(), nil, "push", remote, branch, "-f")
	return err
}

type GitSaveConfig struct {
	AddUntracked bool
	AddIgnored   bool
}

type GitSave struct {
	log  *zap.SugaredLogger
	conf *GitSaveConfig
}

func NewGitSave(logger *zap.Logger, conf *GitSaveConfig) *GitSave {
	return &GitSave{log: logger.Sugar(), conf: conf}
}

// Save adds files to the provided index, creates a tree and a commit pointing to
// that tree, finally it creates a branch poiting to that commit
// Save will use the current worktree index if available to speed the index generation
func (s *GitSave) Save(message, branchName string) error {
	gitdir, err := GitDir()
	if err != nil {
		return err
	}

	tmpIndexPath := filepath.Join(gitdir, "gitsave-index-"+uuid.NewV4().String())
	defer os.Remove(tmpIndexPath)

	indexPath := filepath.Join(gitdir, gitIndexFile)

	curBranch, err := currentGitBranch()
	if err != nil {
		return err
	}

	indexExists, err := fileExists(indexPath)
	if err != nil {
		return err
	}

	if indexExists {
		// copy current git index to a temporary index
		if err := copyFile(indexPath, tmpIndexPath); err != nil {
			return err
		}
		s.log.Infof("created temporary index: %s", tmpIndexPath)
		// read the current branch tree information into the index
		git := &util.Git{Env: []string{"GIT_INDEX_FILE=" + tmpIndexPath}}
		_, err = git.Output(context.Background(), nil, "read-tree", curBranch)
		if err != nil {
			return err
		}
	} else {
		s.log.Infof("index %s does not exist", indexPath)
	}

	s.log.Infof("updating files already in the index")
	if err := gitUpdateFiles(tmpIndexPath); err != nil {
		return err
	}

	if s.conf.AddUntracked {
		s.log.Infof("adding untracked files")
		if err := gitAddUntrackedFiles(tmpIndexPath); err != nil {
			return err
		}
	}

	if s.conf.AddIgnored {
		s.log.Infof("adding ignored files")
		if err := gitAddIgnoredFiles(tmpIndexPath); err != nil {
			return err
		}
	}

	s.log.Infof("writing tree file")
	treeSHA, err := gitWriteTree(tmpIndexPath)
	if err != nil {
		return err
	}
	s.log.Infof("tree: %s", treeSHA)

	s.log.Infof("committing tree")
	commitSHA, err := gitCommitTree(message, treeSHA)
	if err != nil {
		return err
	}
	s.log.Infof("commit: %s", commitSHA)

	s.log.Infof("updating ref")
	if err = gitUpdateRef("git-save", filepath.Join(gitRefsPrefix, branchName), commitSHA); err != nil {
		return err
	}

	return nil
}
