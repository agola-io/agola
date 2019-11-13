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

package notification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"time"

	"agola.io/agola/internal/etcd"
	rstypes "agola.io/agola/services/runservice/types"

	"go.etcd.io/etcd/clientv3/concurrency"
	errors "golang.org/x/xerrors"
)

var (
	etcdRunEventsLockKey = path.Join("locks", "runevents")
)

func (n *NotificationService) runEventsHandlerLoop(ctx context.Context) {
	for {
		if err := n.runEventsHandler(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) runEventsHandler(ctx context.Context) error {
	session, err := concurrency.NewSession(n.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := etcd.NewMutex(session, etcdRunEventsLockKey)

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := n.runserviceClient.GetRunEvents(ctx, "")
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("http status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	stop := false

	var buf bytes.Buffer
	for {
		if stop {
			return nil
		}
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			if len(line) == 0 {
				return nil
			}
			stop = true
		}
		switch {
		case bytes.HasPrefix(line, []byte("data: ")):
			buf.Write(line[6:])
		case bytes.Equal(line, []byte("\n")):
			data := buf.Bytes()
			buf.Reset()

			var ev *rstypes.RunEvent
			if err := json.Unmarshal(data, &ev); err != nil {
				return err
			}

			// TODO(sgotti)
			// this is just a basic handling. Improve it to store received events and
			// their status to etcd so we can also do more logic like retrying and handle
			// multiple kind of notifications (email etc...)
			if err := n.updateCommitStatus(ctx, ev); err != nil {
				log.Infof("failed to update commit status: %v", err)
			}

		default:
			return errors.Errorf("wrong data")
		}
	}
}
