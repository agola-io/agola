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

package executor

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/sorintlab/agola/internal/services/runservice/types"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type taskSubmissionHandler struct {
	c chan<- *types.ExecutorTask
}

func NewTaskSubmissionHandler(c chan<- *types.ExecutorTask) *taskSubmissionHandler {
	return &taskSubmissionHandler{c: c}
}

func (h *taskSubmissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var et *types.ExecutorTask
	d := json.NewDecoder(r.Body)

	if err := d.Decode(&et); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	h.c <- et
}

type logsHandler struct {
	log *zap.SugaredLogger
	e   *Executor
}

func NewLogsHandler(logger *zap.Logger, e *Executor) *logsHandler {
	return &logsHandler{
		log: logger.Sugar(),
		e:   e,
	}
}

func (h *logsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	taskID := q.Get("taskid")
	if taskID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if setup && stepStr != "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}

	follow := false
	_, ok := q["follow"]
	if ok {
		follow = true
	}

	if err := h.readTaskLogs(taskID, setup, step, w, follow); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *logsHandler) readTaskLogs(taskID string, setup bool, step int, w http.ResponseWriter, follow bool) error {
	var logPath string
	if setup {
		logPath = h.e.setupLogPath(taskID)
	} else {
		logPath = h.e.stepLogPath(taskID, step)
	}
	return h.readLogs(taskID, setup, step, logPath, w, follow)
}

func (h *logsHandler) readLogs(taskID string, setup bool, step int, logPath string, w http.ResponseWriter, follow bool) error {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "", http.StatusNotFound)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
		}
		return err
	}
	defer f.Close()

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	buf := make([]byte, 4096)

	// if not following return the Content-Length
	if !follow {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}
	stop := false
	flushstop := false
	for {
		if stop {
			return nil
		}
		n, err := f.Read(buf)
		if err != nil {
			if err != io.EOF {
				return err
			}
			if !flushstop && follow {
				if _, err := f.Seek(-int64(n), io.SeekCurrent); err != nil {
					return errors.Errorf("failed to seek in log file %q: %w", logPath, err)
				}
				// check if the step is finished, if so flush until EOF and stop
				rt, ok := h.e.runningTasks.get(taskID)
				if !ok {
					flushstop = true
				} else {
					rt.Lock()
					if rt.et.Status.Steps[step].Phase.IsFinished() {
						flushstop = true
					}
					rt.Unlock()
				}
				// TODO(sgotti) use ionotify/fswatcher?
				time.Sleep(500 * time.Millisecond)
				continue
			} else {
				stop = true
			}
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

type archivesHandler struct {
	e *Executor
}

func NewArchivesHandler(e *Executor) *archivesHandler {
	return &archivesHandler{e: e}
}

func (h *archivesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	taskID := q.Get("taskid")
	if taskID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	s := q.Get("step")
	if s == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	step, err := strconv.Atoi(s)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")

	if err := h.readArchive(taskID, step, w); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "", http.StatusNotFound)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
		}
		return
	}
}

func (h *archivesHandler) readArchive(taskID string, step int, w http.ResponseWriter) error {
	archivePath := h.e.archivePath(taskID, step)

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}

	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))

	br := bufio.NewReader(f)

	_, err = io.Copy(w, br)
	return err
}
