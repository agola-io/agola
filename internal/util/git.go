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

package util

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"agola.io/agola/internal/errors"
)

// scpSyntaxRe matches the SCP-like addresses used by Git to access repositories
// by SSH.
var scpSyntaxRe = regexp.MustCompile(`^([a-zA-Z0-9_]+)@([a-zA-Z0-9._-]+):(.*)$`)

func ParseGitURL(us string) (*url.URL, error) {
	if m := scpSyntaxRe.FindStringSubmatch(us); m != nil {
		// Match SCP-like syntax and convert it to a URL.
		// Eg, "git@github.com:user/repo" becomes
		// "ssh://git@github.com/user/repo".
		return &url.URL{
			Scheme: "ssh",
			User:   url.User(m[1]),
			Host:   m[2],
			Path:   m[3],
		}, nil
	}

	u, err := url.Parse(us)

	return u, errors.WithStack(err)
}

type Git struct {
	GitDir string
	Env    []string
}

func (g *Git) gitCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	// only keep the PATH, HOME and other useful env vars
	cmdEnv := []string{}
	cmdEnv = append(cmdEnv, "PATH="+os.Getenv("PATH"))
	cmdEnv = append(cmdEnv, "HOME="+os.Getenv("HOME"))
	cmdEnv = append(cmdEnv, "USER="+os.Getenv("USER"))
	if g.GitDir != "" {
		cmdEnv = append(cmdEnv, "GIT_DIR="+g.GitDir)
	}
	cmdEnv = append(cmdEnv, g.Env...)
	cmd.Env = cmdEnv

	return cmd
}

func (g *Git) Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := g.gitCmd(ctx, args...)

	if stdin != nil {
		cmd.Stdin = stdin
	}

	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	out, err := cmd.Output()
	if err != nil {
		gitErr := stderr.String()
		if len(gitErr) > 0 {
			return nil, errors.New(stderr.String())
		} else {
			return nil, errors.WithStack(err)
		}
	}

	return out, errors.WithStack(err)
}

func (g *Git) OutputLines(ctx context.Context, stdin io.Reader, args ...string) ([]string, error) {
	out, err := g.Output(ctx, stdin, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return lines, nil
}

func (g *Git) Pipe(ctx context.Context, w io.Writer, r io.Reader, args ...string) error {
	cmd := g.gitCmd(ctx, args...)

	cmd.Stdin = r

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.WithStack(err)
	}

	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return errors.WithStack(err)
	}
	if _, err := io.Copy(w, stdout); err != nil {
		return errors.WithStack(err)
	}

	if err := cmd.Wait(); err != nil {
		gitErr := stderr.String()
		if len(gitErr) > 0 {
			return errors.New(stderr.String())
		} else {
			return errors.WithStack(err)
		}
	}
	return nil
}

type ErrGitKeyNotFound struct {
	Key string
}

func (e *ErrGitKeyNotFound) Error() string {
	return fmt.Sprintf("key `%q` was not found", e.Key)
}

func (g *Git) ConfigGet(ctx context.Context, args ...string) (string, error) {
	args = append([]string{"config", "--get", "--null"}, args...)
	out, err := g.Output(ctx, nil, args...)

	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
				if waitStatus.ExitStatus() == 1 {
					return "", &ErrGitKeyNotFound{Key: args[len(args)-1]}
				}
			}
		}
		return "", errors.WithStack(err)
	}

	return strings.TrimRight(string(out), "\000"), nil
}

func (g *Git) ConfigSet(ctx context.Context, args ...string) (string, error) {
	args = append([]string{"config", "--null"}, args...)
	out, err := g.Output(ctx, nil, args...)

	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
				if waitStatus.ExitStatus() == 1 {
					return "", &ErrGitKeyNotFound{Key: args[len(args)-1]}
				}
			}
		}
		return "", errors.WithStack(err)
	}

	return strings.TrimRight(string(out), "\000"), nil
}
