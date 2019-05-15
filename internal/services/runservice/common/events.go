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

package common

import (
	"context"

	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/runservice/types"
)

func NewRunEvent(ctx context.Context, e *etcd.Store, runID string, phase types.RunPhase, result types.RunResult) (*types.RunEvent, error) {
	seq, err := sequence.IncSequence(ctx, e, EtcdRunEventSequenceKey)
	if err != nil {
		return nil, err
	}
	return &types.RunEvent{Sequence: seq.String(), RunID: runID, Phase: phase, Result: result}, nil
}
