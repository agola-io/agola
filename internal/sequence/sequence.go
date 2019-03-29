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

package sequence

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/etcd"
)

type Sequence struct {
	Epoch uint64
	C     uint64
}

func (s *Sequence) String() string {
	// 1<<64 -1 in base 32 is "3w5e11264sgsf" and uses 13 chars
	return fmt.Sprintf("%013s-%013s", strconv.FormatUint(s.Epoch, 32), strconv.FormatUint(s.C, 32))
}

func (s *Sequence) Reverse() *Sequence {
	return &Sequence{
		Epoch: math.MaxUint64 - s.Epoch,
		C:     math.MaxUint64 - s.C,
	}
}

func Parse(s string) (*Sequence, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, errors.Errorf("bad sequence %q", s)
	}
	epoch, err := strconv.ParseUint(parts[0], 32, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse sequence epoch %q", epoch)
	}
	c, err := strconv.ParseUint(parts[1], 32, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse sequence count %q", c)
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
