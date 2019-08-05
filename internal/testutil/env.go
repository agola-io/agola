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

package testutil

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
)

func ParseEnv(envvar string) (string, string, error) {
	// trim white spaces at the start
	envvar = strings.TrimLeftFunc(envvar, unicode.IsSpace)
	arr := strings.SplitN(envvar, "=", 2)
	if len(arr) == 0 {
		return "", "", fmt.Errorf("invalid environment variable definition: %s", envvar)
	}
	varname := arr[0]
	if varname == "" {
		return "", "", fmt.Errorf("invalid environment variable definition: %s", envvar)
	}
	if len(arr) == 1 {
		return varname, "", nil
	}
	return varname, arr[1], nil
}

func ParseEnvs(r io.Reader) (map[string]string, error) {
	envs := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		envname, envvalue, err := ParseEnv(scanner.Text())
		if err != nil {
			return nil, err
		}
		envs[envname] = envvalue
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envs, nil
}
