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
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	handlers "agola.io/agola/internal/git-handler"
	slog "agola.io/agola/internal/log"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

const (
	gitSuffix = ".git"
)

func repoPathIsValid(reposDir, repoPath string) (bool, error) {
	// a parent cannot end with .git
	parts := strings.Split(repoPath, "/")
	for _, part := range parts[:len(parts)-1] {
		if strings.HasSuffix(part, gitSuffix) {
			return false, errors.Errorf("path %q contains a parent directory with .git suffix", repoPath)
		}
	}

	// check that a subdirectory doesn't exists
	reposDir, err := filepath.Abs(reposDir)
	if err != nil {
		return false, err
	}

	path := repoPath
	_, err = os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if !os.IsNotExist(err) {
		// if it exists assume it's valid
		return true, nil
	}

	for {
		path = filepath.Dir(path)
		if len(path) <= len(reposDir) {
			break
		}

		_, err := os.Stat(path)
		if err != nil && !os.IsNotExist(err) {
			return false, err
		}
		// a parent path cannot end with .git
		if strings.HasSuffix(path, gitSuffix) {
			return false, nil
		}
		if !os.IsNotExist(err) {
			// if a parent exists return not valid
			return false, nil
		}
	}

	return true, nil
}

func repoExists(repoAbsPath string) (bool, error) {
	_, err := os.Stat(repoAbsPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return !os.IsNotExist(err), nil
}

func repoAbsPath(reposDir, repoPath string) (string, bool, error) {
	valid, err := repoPathIsValid(reposDir, repoPath)
	if err != nil {
		return "", false, err
	}
	if !valid {
		return "", false, handlers.ErrWrongRepoPath
	}

	repoFSPath, err := filepath.Abs(filepath.Join(reposDir, repoPath))
	if err != nil {
		return "", false, err
	}

	exists, err := repoExists(repoFSPath)
	if err != nil {
		return "", false, err
	}

	return repoFSPath, exists, nil
}

func Matcher(matchRegexp *regexp.Regexp) mux.MatcherFunc {
	return func(r *http.Request, rm *mux.RouteMatch) bool {
		return matchRegexp.MatchString(r.URL.Path)
	}
}

type Gitserver struct {
	c *config.Gitserver
}

func NewGitserver(ctx context.Context, l *zap.Logger, c *config.Gitserver) (*Gitserver, error) {
	if l != nil {
		logger = l
	}
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}
	log = logger.Sugar()

	return &Gitserver{
		c: c,
	}, nil
}

func (s *Gitserver) Run(ctx context.Context) error {
	gitSmartHandler := handlers.NewGitSmartHandler(logger, s.c.DataDir, true, repoAbsPath, nil)
	fetchFileHandler := handlers.NewFetchFileHandler(logger, s.c.DataDir, repoAbsPath)

	router := mux.NewRouter()
	router.MatcherFunc(Matcher(handlers.InfoRefsRegExp)).Handler(gitSmartHandler)
	router.MatcherFunc(Matcher(handlers.UploadPackRegExp)).Handler(gitSmartHandler)
	router.MatcherFunc(Matcher(handlers.ReceivePackRegExp)).Handler(gitSmartHandler)
	router.MatcherFunc(Matcher(handlers.FetchFileRegExp)).Handler(fetchFileHandler)

	var tlsConfig *tls.Config
	if s.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(s.c.Web.TLSCertFile, s.c.Web.TLSKeyFile, "", false)
		if err != nil {
			log.Errorf("err: %+v")
			return err
		}
	}

	httpServer := http.Server{
		Addr:      s.c.Web.ListenAddress,
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Infof("gitserver exiting")
		httpServer.Close()
	case err := <-lerrCh:
		if err != nil {
			log.Errorf("http server listen error: %v", err)
			return err
		}
	}

	return nil
}
