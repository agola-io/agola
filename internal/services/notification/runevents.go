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
	"time"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/lock"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	RunEventsLockKey = "runevents"
)

func (n *NotificationService) runEventsHandlerLoop(ctx context.Context) {
	for {
		if err := n.runEventsHandler(ctx); err != nil {
			n.log.Err(err).Send()
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
	l := n.lf.NewLock(RunEventsLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	resp, err := n.runserviceClient.GetRunEvents(ctx, "")
	if err != nil {
		return errors.WithStack(err)
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
				return errors.WithStack(err)
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
				return errors.WithStack(err)
			}

			// TODO(sgotti)
			// this is just a basic handling. Improve it to store received events and
			// their status in the db so we can also do more logic like retrying and handle
			// multiple kind of notifications (email etc...)
			if err := n.updateCommitStatus(ctx, ev); err != nil {
				n.log.Info().Msgf("failed to update commit status: %v", err)
			}

		default:
			return errors.Errorf("wrong data")
		}
	}
}
