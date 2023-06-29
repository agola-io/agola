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

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mitchellh/copystructure"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/notification"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
)

const signatureSHA256Key = "X-Agola-SHA256Signature"

type webhooksReceiver struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	log zerolog.Logger

	t   *testing.T
	dir string

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
	webhookData *notification.RunWebhook
	signature   string
}

func (ws *webhooks) getWebhooks() ([]*webhook, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	retVal := make([]*webhook, len(ws.webhooks))
	for i, w := range ws.webhooks {
		nr, err := copystructure.Copy(w.webhookData)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to copy webhooks")
		}
		v := nr.(*notification.RunWebhook)

		retVal[i] = &webhook{webhookData: v, signature: w.signature}
	}

	return retVal, nil
}

func (ws *webhooks) addWebhook(webhook *webhook) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	ws.webhooks = append(ws.webhooks, webhook)
}

func setupWebhooksReceiver(pctx context.Context, t *testing.T, dir string) *webhooksReceiver {
	log := testutil.NewLogger(t)
	ctx, cancel := context.WithCancel(pctx)

	ws := &webhooks{webhooks: make([]*webhook, 0)}
	wr := &webhooksReceiver{ctx: ctx, t: t, dir: dir, log: log, cancel: cancel, webhooks: ws}

	dockerBridgeAddress := os.Getenv("DOCKER_BRIDGE_ADDRESS")
	if dockerBridgeAddress == "" {
		dockerBridgeAddress = "172.17.0.1"
	}

	port, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	wr.listenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, port)
	wr.exposedURL = fmt.Sprintf("http://%s:%s", dockerBridgeAddress, port)

	if err := wr.start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.ListenAndServe()
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
	var req *notification.RunWebhook
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		h.log.Err(err).Send()
		return
	}

	signature := r.Header.Get(signatureSHA256Key)

	h.webhooks.addWebhook(&webhook{webhookData: req, signature: signature})

	if err := util.HTTPResponse(w, http.StatusCreated, nil); err != nil {
		h.log.Err(err).Send()
	}
}
