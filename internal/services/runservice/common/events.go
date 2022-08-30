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
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/runservice/types"
)

func NewRunEvent(d *db.DB, tx *sql.Tx, runID string, phase types.RunPhase, result types.RunResult) (*types.RunEvent, error) {
	runEvent := types.NewRunEvent()
	runEvent.RunID = runID
	runEvent.Phase = phase
	runEvent.Result = result

	runEventSequence, err := d.NextSequence(tx, types.SequenceTypeRunEvent)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	runEvent.Sequence = runEventSequence

	return runEvent, nil
}
