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
