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
	"errors"
	"regexp"

	uuid "github.com/satori/go.uuid"
)

var nameRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*([-]?[a-zA-Z0-9]+)+$`)

var (
	ErrValidation = errors.New("validation error")
)

func ValidateName(s string) bool {
	// names that are valid uuids are not valid. This is needed to accept both
	// names or uuid in rest APIs
	if _, err := uuid.FromString(s); err == nil {
		return false
	}
	return nameRegexp.MatchString(s)
}
