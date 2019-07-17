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
	"net/url"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const (
	EtcdMaintenanceKey = "maintenance"
)

type RefType int

const (
	RefTypeID RefType = iota
	RefTypePath
	RefTypeName
)

// ParseRef parses the api call to determine if the provided ref is
// an ID or a path
func ParsePathRef(ref string) (RefType, error) {
	ref, err := url.PathUnescape(ref)
	if err != nil {
		return -1, err
	}
	if strings.Contains(ref, "/") {
		return RefTypePath, nil
	}
	return RefTypeID, nil
}

// ParseRef parses the api call to determine if the provided ref is
// an ID or a name
func ParseNameRef(ref string) (RefType, error) {
	if _, err := uuid.FromString(ref); err == nil {
		return RefTypeID, nil
	}
	return RefTypeName, nil
}
