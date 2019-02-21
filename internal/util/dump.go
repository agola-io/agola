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
// level is lesser than debug.
type dump struct {
	data interface{}
}

func (d *dump) Format(f fmt.State, c rune) {
	f.Write([]byte(litter.Sdump(d.data)))
}

func Dump(data interface{}) *dump {
	return &dump{data: data}
}
