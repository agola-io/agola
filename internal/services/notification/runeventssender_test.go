// Copyright 2023 Sorint.lab
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

package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
)

type runEventsSender struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	log zerolog.Logger

	t *testing.T

	mu sync.Mutex

	listenAddress string
	exposedURL    string

	runEvents *runEvents
}

type runEvents struct {
	runEvents []*types.RunEvent
	mu        sync.Mutex
}

func (r *runEvents) addRunEvent(runEvent *types.RunEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.runEvents = append(r.runEvents, runEvent)
}

func setupRunEventsSender(pctx context.Context, t *testing.T) *runEventsSender {
	log := testutil.NewLogger(t)
	ctx, cancel := context.WithCancel(pctx)

	r := &runEvents{runEvents: make([]*types.RunEvent, 0)}
	es := &runEventsSender{ctx: ctx, t: t, log: log, cancel: cancel, runEvents: r}

	port, err := testutil.GetFreePort("localhost", true, false)
	testutil.NilError(t, err)

	es.listenAddress = net.JoinHostPort("localhost", port)
	es.exposedURL = fmt.Sprintf("http://%s", net.JoinHostPort("localhost", port))
	err = es.start()
	testutil.NilError(t, err)

	go func() {
		<-ctx.Done()

		es.stop()
	}()

	return es
}

func (es *runEventsSender) start() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if es.started {
		return fmt.Errorf("runEventsSender already started")
	}

	router := mux.NewRouter()

	router.Handle("/api/v1alpha/runs/events", newRunEventsHandler(es.log, es.runEvents)).Methods("GET")

	httpServer := http.Server{
		Addr:    es.listenAddress,
		Handler: router,
	}

	ln, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return errors.WithStack(err)
	}

	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.Serve(ln)
	}()

	go func() {
		select {
		case <-es.ctx.Done():
			httpServer.Close()
		case err := <-lerrCh:
			if err != nil {
				es.log.Err(err).Send()
			}
		}
	}()

	es.started = true

	return nil
}

func (es *runEventsSender) stop() {
	es.mu.Lock()
	defer es.mu.Unlock()

	if !es.started {
		return
	}

	es.cancel()
	es.started = false
}

type runEventsHandler struct {
	log       zerolog.Logger
	runEvents *runEvents
}

func newRunEventsHandler(log zerolog.Logger, runEvents *runEvents) *runEventsHandler {
	return &runEventsHandler{log: log, runEvents: runEvents}
}

func (h *runEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	q := r.URL.Query()
	var afterRunEventSequence uint64
	afterRunEventSequenceStr := q.Get("afterSequence")
	if afterRunEventSequenceStr != "" {
		var err error
		afterRunEventSequence, err = strconv.ParseUint(afterRunEventSequenceStr, 10, 64)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse afterSequence")))
			return
		}
	}

	h.runEvents.mu.Lock()
	defer h.runEvents.mu.Unlock()

	sort.Slice(h.runEvents.runEvents, func(i, j int) bool {
		return h.runEvents.runEvents[i].Sequence < h.runEvents.runEvents[j].Sequence
	})

	for _, runEvent := range h.runEvents.runEvents {
		if runEvent.Sequence <= afterRunEventSequence {
			continue
		}

		runEventj, err := json.Marshal(runEvent)
		if err != nil {
			h.log.Err(err).Send()
		}

		if _, err := w.Write([]byte(fmt.Sprintf("data: %s\n\n", runEventj))); err != nil {
			h.log.Err(err).Send()
		}
	}
}
