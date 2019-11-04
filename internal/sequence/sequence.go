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

package sequence

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"agola.io/agola/internal/etcd"
	errors "golang.org/x/xerrors"
)

type Sequence struct {
	Epoch uint64
	C     uint64
}

func (s *Sequence) String() string {
	// 1<<64 -1 in base 32 is "fvvvvvvvvvvvv" and uses 13 chars
	return fmt.Sprintf("%013s-%013s", strconv.FormatUint(s.Epoch, 32), strconv.FormatUint(s.C, 32))
}

func (s *Sequence) Reverse() *Sequence {
	return &Sequence{
		Epoch: math.MaxUint64 - s.Epoch,
		C:     math.MaxUint64 - s.C,
	}
}

func Parse(s string) (*Sequence, error) {
	if len(s) != 13*2+1 {
		return nil, errors.Errorf("bad sequence %q string length", s)
	}

	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, errors.Errorf("bad sequence %q", s)
	}
	epoch, err := strconv.ParseUint(parts[0], 32, 64)
	if err != nil {
		return nil, errors.Errorf("cannot parse sequence epoch %q: %w", epoch, err)
	}
	c, err := strconv.ParseUint(parts[1], 32, 64)
	if err != nil {
		return nil, errors.Errorf("cannot parse sequence count %q: %w", c, err)
	}
	return &Sequence{
		Epoch: epoch,
		C:     c,
	}, nil
}

func (s *Sequence) EqualEpoch(s2 *Sequence) bool {
	return s.Epoch == s2.Epoch
}

func CurSequence(ctx context.Context, e *etcd.Store, key string) (*Sequence, bool, error) {
	resp, err := e.Get(ctx, key, 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, false, err
	}
	if err == etcd.ErrKeyNotFound {
		return nil, false, nil
	}

	seq := &Sequence{}
	if err != etcd.ErrKeyNotFound {
		kv := resp.Kvs[0]
		if err := json.Unmarshal(kv.Value, &seq); err != nil {
			return nil, false, err
		}
	}
	return seq, true, nil
}

func IncSequence(ctx context.Context, e *etcd.Store, key string) (*Sequence, error) {
	resp, err := e.Get(ctx, key, 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}

	var revision int64
	seq := &Sequence{}
	if err != etcd.ErrKeyNotFound {
		kv := resp.Kvs[0]
		if err := json.Unmarshal(kv.Value, &seq); err != nil {
			return nil, err
		}
		revision = kv.ModRevision
	}

	// if the epoch is zero then this is a new etcd cluster. This will happen on
	// first creation or if the etcd cluster is recreated. The epoch is used to
	// keep the seq incremental and we assume the new epoch will always be greater
	// than the previous ones (it not then there was a big backward time drift)
	//
	// TODO(sgotti) check that the new epoch is greater then previous ones???
	if seq.Epoch == 0 {
		seq.Epoch = uint64(time.Now().Unix())
	}

	seq.C++

	seqj, err := json.Marshal(seq)
	if err != nil {
		return nil, err
	}

	_, err = e.AtomicPut(ctx, key, seqj, revision, nil)
	if err != nil {
		return nil, err
	}

	return seq, nil
}
