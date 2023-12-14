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
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mitchellh/copystructure"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
)

type webhooksReceiver struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	log zerolog.Logger

	t *testing.T

	mu sync.Mutex

	listenAddress string
	exposedURL    string

	webhooks *webhooks
}

type webhooks struct {
	webhooks []*webhook
	mu       sync.Mutex
}

type webhook struct {
	Payload   []byte
	Signature string
}

func (ws *webhooks) getWebhooks() ([]*webhook, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	retVal := make([]*webhook, len(ws.webhooks))
	for i, w := range ws.webhooks {
		nr, err := copystructure.Copy(w)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to copy webhooks")
		}
		v := nr.(*webhook)

		retVal[i] = v
	}

	return retVal, nil
}

func (ws *webhooks) addWebhook(webhook *webhook) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	ws.webhooks = append(ws.webhooks, webhook)
}

func (ws *webhooks) resetWebhooks() {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	ws.webhooks = ws.webhooks[:0]
}

func setupWebhooksReceiver(pctx context.Context, t *testing.T) *webhooksReceiver {
	log := testutil.NewLogger(t)
	ctx, cancel := context.WithCancel(pctx)

	ws := &webhooks{webhooks: make([]*webhook, 0)}
	wr := &webhooksReceiver{ctx: ctx, t: t, log: log, cancel: cancel, webhooks: ws}

	port, err := testutil.GetFreePort("localhost", true, false)
	testutil.NilError(t, err)

	wr.listenAddress = net.JoinHostPort("localhost", port)
	wr.exposedURL = fmt.Sprintf("http://%s", net.JoinHostPort("localhost", port))
	err = wr.start()
	testutil.NilError(t, err)

	go func() {
		<-ctx.Done()

		wr.stop()
	}()

	return wr
}

func (wr *webhooksReceiver) start() error {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if wr.started {
		return fmt.Errorf("webhooksReceiver already started")
	}

	router := mux.NewRouter()

	router.Handle("/webhooks", newHandleWebhookHandler(wr.log, wr.webhooks)).Methods("POST")

	httpServer := http.Server{
		Addr:    wr.listenAddress,
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
		case <-wr.ctx.Done():
			httpServer.Close()
		case err := <-lerrCh:
			if err != nil {
				wr.log.Err(err).Send()
			}
		}
	}()

	wr.started = true

	return nil
}

func (wr *webhooksReceiver) stop() {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if !wr.started {
		return
	}

	wr.cancel()
	wr.started = false
}

type handleWebhookHandler struct {
	log      zerolog.Logger
	webhooks *webhooks
}

func newHandleWebhookHandler(log zerolog.Logger, webhooks *webhooks) *handleWebhookHandler {
	return &handleWebhookHandler{log: log, webhooks: webhooks}
}

func (h *handleWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	signature := r.Header.Get(signatureSHA256Key)

	h.webhooks.addWebhook(&webhook{Payload: body, Signature: signature})

	if err := util.HTTPResponse(w, http.StatusCreated, nil); err != nil {
		h.log.Err(err).Send()
	}
}
