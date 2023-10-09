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
	"sync"

	"github.com/mitchellh/copystructure"
	"github.com/sorintlab/errors"

	"agola.io/agola/services/notification/types"
)

type StubCommitStatusUpdater struct {
	mu                     sync.Mutex
	commitStatuses         *commitStatuses
	failUpdateCommitStatus bool
}

func setupStubCommitStatusUpdater() *StubCommitStatusUpdater {
	cs := &commitStatuses{commitStatuses: make([]*types.CommitStatus, 0)}
	return &StubCommitStatusUpdater{commitStatuses: cs}
}

func (u *StubCommitStatusUpdater) setFailUpdateCommitStatus(failUpdateCommitStatus bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.failUpdateCommitStatus = failUpdateCommitStatus
}

func (u *StubCommitStatusUpdater) updateCommitStatus(ctx context.Context, cs *types.CommitStatus) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.failUpdateCommitStatus {
		return false, errors.Errorf("updateCommitStatus failed")
	}

	u.commitStatuses.addCommitStatuses(cs)

	return true, nil
}

type commitStatuses struct {
	commitStatuses []*types.CommitStatus
	mu             sync.Mutex
}

func (cs *commitStatuses) getCommitStatuses() ([]*types.CommitStatus, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	retVal := make([]*types.CommitStatus, len(cs.commitStatuses))
	for i, w := range cs.commitStatuses {
		nr, err := copystructure.Copy(w)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to copy webhooks")
		}
		v := nr.(*types.CommitStatus)

		retVal[i] = v
	}

	return retVal, nil
}

func (cs *commitStatuses) addCommitStatuses(commitStatus *types.CommitStatus) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.commitStatuses = append(cs.commitStatuses, commitStatus)
}

func (cs *commitStatuses) resetCommitStatuses() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.commitStatuses = cs.commitStatuses[:0]
}
