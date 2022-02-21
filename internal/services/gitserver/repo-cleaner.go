package gitserver

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"agola.io/agola/internal/util"
)

func (s *Gitserver) repoCleanerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.log.Info().Msgf("repoCleaner exiting")

			return
		case <-time.After(s.c.RepositoryCleanupInterval):
			if err := s.scanRepos(ctx); err != nil {
				s.log.Err(err).Msgf("scanRepos error")
			}
		}
	}
}

func (s *Gitserver) scanRepos(ctx context.Context) error {
	s.log.Info().Msgf("repoCleaner scanRepos start")

	usersDir, err := ioutil.ReadDir(s.c.DataDir)
	if err != nil {
		return err
	}

	for _, u := range usersDir {
		if !u.IsDir() {
			continue
		}

		reposDir, _ := ioutil.ReadDir(filepath.Join(s.c.DataDir, u.Name()))
		for _, r := range reposDir {
			if !r.IsDir() {
				continue
			}

			if err := s.scanRepo(ctx, filepath.Join(s.c.DataDir, u.Name(), r.Name())); err != nil {
				s.log.Err(err).Msgf("scanRepo error")
			}
		}
	}

	s.log.Info().Msgf("repoCleaner scanRepos end")

	return nil
}

func (s *Gitserver) scanRepo(ctx context.Context, repoDir string) error {
	git := &util.Git{GitDir: repoDir}

	branches, _ := s.getBranches(git, ctx)
	for _, b := range branches {
		committerTime, err := s.getLastCommiterTime(ctx, git, "refs/heads/"+b)
		if err != nil {
			return fmt.Errorf("return failed to get last commit time: %w", err)
		}

		if time.Since(committerTime) >= s.c.RepositoryRefsExpireInterval {
			if err := s.deleteBranch(ctx, git, b); err != nil {
				return fmt.Errorf("failed to delete git branch: %w", err)
			}
		}
	}

	tags, _ := s.getTags(git, ctx)
	for _, tag := range tags {
		committerTime, err := s.getLastCommiterTime(ctx, git, "refs/tags/"+tag)
		if err != nil {
			return fmt.Errorf("failed to get last commit time: %w", err)
		}

		if time.Since(committerTime) >= s.c.RepositoryRefsExpireInterval {
			if err := s.deleteTag(ctx, git, tag); err != nil {
				return fmt.Errorf("failed to delete git tag: %w", err)
			}
		}
	}

	if _, err := git.Output(ctx, nil, "prune"); err != nil {
		return fmt.Errorf("git prune failed: %w", err)
	}

	b, err := s.getBranches(git, ctx)
	if err != nil {
		return fmt.Errorf("failed to get git branches: %w", err)
	}

	t, err := s.getTags(git, ctx)
	if err != nil {
		return fmt.Errorf("failed to get git tags: %w", err)
	}

	if len(b) == 0 && len(t) == 0 {
		s.log.Info().Msgf("deleting repo: %q", repoDir)
		if err := s.deleteRepo(ctx, repoDir); err != nil {
			return fmt.Errorf("failed to delete repository: %w", err)
		}
	}

	return nil
}

func (s *Gitserver) getBranches(git *util.Git, ctx context.Context) ([]string, error) {
	branches, err := git.OutputLines(ctx, nil, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
	if err != nil {
		return nil, err
	}

	return branches, nil
}

func (s *Gitserver) getTags(git *util.Git, ctx context.Context) ([]string, error) {
	tags, err := git.OutputLines(ctx, nil, "for-each-ref", "--format=%(refname:short)", "refs/tags/")
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func (s *Gitserver) getLastCommiterTime(ctx context.Context, git *util.Git, ref string) (time.Time, error) {
	output, err := git.OutputLines(ctx, nil, "log", "-1", "--format=%cI", ref)
	if err != nil {
		return time.Time{}, err
	}

	if len(output) != 1 {
		return time.Time{}, errors.New("git log error: must return one line")
	}

	committerTime, err := time.Parse(time.RFC3339, output[0])
	if err != nil {
		return time.Time{}, err
	}

	return committerTime, nil
}

func (s *Gitserver) deleteBranch(ctx context.Context, git *util.Git, branch string) error {
	_, err := git.Output(ctx, nil, "branch", "-D", branch)
	return err
}

func (s *Gitserver) deleteTag(ctx context.Context, git *util.Git, tag string) error {
	_, err := git.Output(ctx, nil, "tag", "-d", tag)
	return err
}

func (s *Gitserver) deleteRepo(ctx context.Context, repoDir string) error {
	return os.RemoveAll(repoDir)
}
