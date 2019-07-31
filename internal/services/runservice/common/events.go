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

package common

import (
	"context"

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/sequence"
	"agola.io/agola/services/runservice/types"
)

func NewRunEvent(ctx context.Context, e *etcd.Store, runID string, phase types.RunPhase, result types.RunResult) (*types.RunEvent, error) {
	seq, err := sequence.IncSequence(ctx, e, EtcdRunEventSequenceKey)
	if err != nil {
		return nil, err
	}
	return &types.RunEvent{Sequence: seq.String(), RunID: runID, Phase: phase, Result: result}, nil
}
