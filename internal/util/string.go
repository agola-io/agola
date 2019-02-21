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
	"bufio"
	"io"
	"strings"
)

func CountLines(s string) (uint, error) {
	count := uint(0)

	// use a reader instead of a scanner
	br := bufio.NewReader(strings.NewReader(s))

	stop := false
	for {
		if stop {
			break
		}
		_, err := br.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return 0, err
			}
			stop = true
		}
		count++
	}
	return count, nil
}
