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
)

type RunEventType string

const (
	RunEventTypeQueued    RunEventType = "queued"
	RunEventTypeCancelled RunEventType = "cancelled"
	RunEventTypeRunning   RunEventType = "running"
	RunEventTypeSuccess   RunEventType = "success"
	RunEventTypeFailed    RunEventType = "failed"
)

type RunEvent struct {
	Sequence  string
	EventType RunEventType
	RunID     string
}

func NewRunEvent(ctx context.Context, e *etcd.Store, runEventType RunEventType, runID string) (*RunEvent, error) {
	seq, err := sequence.IncSequence(ctx, e, EtcdRunEventSequenceKey)
	if err != nil {
		return nil, err
	}
	return &RunEvent{Sequence: seq.String(), EventType: runEventType, RunID: runID}, nil
}
