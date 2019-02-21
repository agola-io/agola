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

package util

import (
	"fmt"

	"github.com/sanity-io/litter"
)

// dump implements the fmt.Formatter interface and can be used instead of a
// direct call to litter.Sdump.
// In this way litter.Sdump will be executed only when really needed without
// consuming CPU when not required.
// I.E. if logging with zap using log.Debugf("dumped value: ", util.Dump(value)),
// the formatting (and so the call to litter.Sdump) won't happen if the log
// level is less than debug.
type dump struct {
	data interface{}
}

func (d *dump) Format(f fmt.State, c rune) {
	f.Write([]byte(litter.Sdump(d.data)))
}

func Dump(data interface{}) *dump {
	return &dump{data: data}
}
