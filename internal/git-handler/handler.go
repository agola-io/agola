package githandler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
	"go.uber.org/zap"
)

var (
	InfoRefsRegExp    = regexp.MustCompile(`/(.+\.git)/info/refs$`)
	UploadPackRegExp  = regexp.MustCompile(`/(.+\.git)/git-upload-pack$`)
	ReceivePackRegExp = regexp.MustCompile(`/(.+\.git)/git-receive-pack$`)

	FetchFileRegExp = regexp.MustCompile(`/(.+\.git)/raw/(.+?)/(.+)`)
)

type RequestType int

const (
	RequestTypeInfoRefs RequestType = iota
	RequestTypeUploadPack
	RequestTypeReceivePack
)

type FetchFileData struct {
	RepoPath string
	Ref      string
	Path     string
}

func ParseFetchFilePath(path string) (*FetchFileData, error) {
	matches := FetchFileRegExp.FindStringSubmatch(path)
	if len(matches) != 4 {
		return nil, errors.New("cannot get fetch file data from url")
	}
	return &FetchFileData{
		RepoPath: matches[1],
		Ref:      matches[2],
		Path:     matches[3],
	}, nil
}

func MatchPath(path string) (string, RequestType, error) {
	var matchedRegExp *regexp.Regexp
	var reqType RequestType
	for i, regExp := range []*regexp.Regexp{InfoRefsRegExp, UploadPackRegExp, ReceivePackRegExp} {
		if regExp.MatchString(path) {
			matchedRegExp = regExp
			reqType = RequestType(i)
		}
	}
	if matchedRegExp == nil {
		return "", 0, errors.New("wrong request path")
	}

	matches := matchedRegExp.FindStringSubmatch(path)
	if len(matches) != 2 {
		return "", 0, errors.New("cannot get repository path from url")
	}
	return matches[1], reqType, nil
}

func gitServiceName(r *http.Request) (string, error) {
	service := r.URL.Query().Get("service")
	if !strings.HasPrefix(service, "git-") {
		return "", errors.Errorf("wrong git service %q", service)
	}
	return strings.TrimPrefix(service, "git-"), nil
}

func writePacketLine(w io.Writer, line string) {
	fmt.Fprintf(w, "%.4x%s\n", len(line)+5, line)
}

func writeFlushPacket(w io.Writer) {
	fmt.Fprintf(w, "0000")
}

func InfoRefsResponse(ctx context.Context, repoPath, serviceName string) ([]byte, error) {
	buf := &bytes.Buffer{}

	writePacketLine(buf, "# service=git-"+serviceName)
	writeFlushPacket(buf)

	git := &util.Git{}
	out, err := git.Output(ctx, nil, serviceName, "--stateless-rpc", "--advertise-refs", repoPath)
	if err != nil {
		return nil, err
	}
	buf.Write(out)

	return buf.Bytes(), err
}

func gitService(ctx context.Context, w io.Writer, r io.Reader, repoPath, serviceName string) error {
	git := &util.Git{GitDir: repoPath}
	return git.Pipe(ctx, w, r, serviceName, "--stateless-rpc", repoPath)
}

func gitFetchFile(ctx context.Context, w io.Writer, r io.Reader, repoPath, ref, path string) error {
	git := &util.Git{GitDir: repoPath}
	return git.Pipe(ctx, w, r, "show", fmt.Sprintf("%s:%s", ref, path))
}

var ErrWrongRepoPath = errors.New("wrong repository path")

// RepoAbsPathFunc is a user defined functions that, given the repo path
// provided in the url request, will return the file system absolute repo path
// and if it exists.
// This function should also do path validation and return ErrWrongRepoPath if
// path validation failed.
type RepoAbsPathFunc func(reposDir, path string) (absPath string, exists bool, err error)

type RepoPostCreateFunc func(repoPath, repoAbsPath string) error

type GitSmartHandler struct {
	log                *zap.SugaredLogger
	reposDir           string
	createRepo         bool
	repoAbsPathFunc    RepoAbsPathFunc
	repoPostCreateFunc RepoPostCreateFunc
}

func NewGitSmartHandler(logger *zap.Logger, reposDir string, createRepo bool, repoAbsPathFunc RepoAbsPathFunc, repoPostCreateFunc RepoPostCreateFunc) *GitSmartHandler {
	return &GitSmartHandler{
		log:                logger.Sugar(),
		reposDir:           reposDir,
		createRepo:         createRepo,
		repoAbsPathFunc:    repoAbsPathFunc,
		repoPostCreateFunc: repoPostCreateFunc,
	}
}

func (h *GitSmartHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	repoPath, reqType, err := MatchPath(r.URL.Path)
	h.log.Infof("repoPath: %s", repoPath)
	repoAbsPath, exists, err := h.repoAbsPathFunc(h.reposDir, repoPath)
	if err != nil {
		if err == ErrWrongRepoPath {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.log.Infof("repoAbsPath: %s", repoAbsPath)
	h.log.Infof("repo exists: %t", exists)

	git := &util.Git{GitDir: repoAbsPath}

	switch reqType {
	case RequestTypeInfoRefs:
		if h.createRepo && !exists {
			if output, err := git.Output(ctx, nil, "init", "--bare", repoAbsPath); err != nil {
				h.log.Infof("git error %v, output: %s", err, output)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if h.repoPostCreateFunc != nil {
				if err := h.repoPostCreateFunc(repoPath, repoAbsPath); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}

		serviceName, err := gitServiceName(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := InfoRefsResponse(ctx, repoAbsPath, serviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/x-git-"+serviceName+"-advertisement")
		w.Write(res)

	case RequestTypeUploadPack:
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")

		if err := gitService(ctx, w, r.Body, repoAbsPath, "upload-pack"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// we cannot return any http error since the http header has already been written
			h.log.Infof("git command error: %v", err)
		}
	case RequestTypeReceivePack:
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")

		if err := gitService(ctx, w, r.Body, repoAbsPath, "receive-pack"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			// we cannot return any http error since the http header has already been written
			h.log.Infof("git command error: %v", err)
		}
	}
}

type FetchFileHandler struct {
	log             *zap.SugaredLogger
	reposDir        string
	repoAbsPathFunc RepoAbsPathFunc
}

func NewFetchFileHandler(logger *zap.Logger, reposDir string, repoAbsPathFunc RepoAbsPathFunc) *FetchFileHandler {
	return &FetchFileHandler{
		log:             logger.Sugar(),
		reposDir:        reposDir,
		repoAbsPathFunc: repoAbsPathFunc,
	}
}

func (h *FetchFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	fetchData, err := ParseFetchFilePath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.log.Infof("fetchData: %v", fetchData)

	repoAbsPath, _, err := h.repoAbsPathFunc(h.reposDir, fetchData.RepoPath)
	if err != nil {
		if err == ErrWrongRepoPath {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := gitFetchFile(ctx, w, r.Body, repoAbsPath, fetchData.Ref, fetchData.Path); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// we cannot return any http error since the http header has already been written
		h.log.Infof("git command error: %v", err)
	}
}
