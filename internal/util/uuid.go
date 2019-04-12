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
	uuid "github.com/satori/go.uuid"
)

type UUIDGenerator interface {
	New(s string) uuid.UUID
}

type DefaultUUIDGenerator struct{}

func (u DefaultUUIDGenerator) New(s string) uuid.UUID {
	return uuid.NewV4()
}

type TestUUIDGenerator struct{}

func (u TestUUIDGenerator) New(s string) uuid.UUID {
	return uuid.NewV5(uuid.NamespaceDNS, s)
}

type TestPrefixUUIDGenerator struct{ Prefix string }

func (u TestPrefixUUIDGenerator) New(s string) uuid.UUID {
	return uuid.NewV5(uuid.NamespaceDNS, u.Prefix+s)
}
