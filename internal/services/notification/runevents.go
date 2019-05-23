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

	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"

	errors "golang.org/x/xerrors"
	"go.etcd.io/etcd/clientv3/concurrency"
)

var (
	etcdRunEventsLockKey = path.Join("locks", "runevents")
)

func (n *NotificationService) runEventsHandlerLoop(ctx context.Context) {
	for {
		if err := n.runEventsHandler(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (n *NotificationService) runEventsHandler(ctx context.Context) error {
	session, err := concurrency.NewSession(n.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdRunEventsLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

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
			log.Infof("data: %s", data)
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
