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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

// EncodeSha1Hex generates sha1 from string and returns its hex encoding
func EncodeSha1Hex(str string) string {
	h := sha1.New()
	// TODO(sgotti) must handle write errors
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// EncodeSha1Hex generates sha1 from string and returns its hex encoding
func EncodeSha256Hex(str string) string {
	h := sha256.New()
	// TODO(sgotti) must handle write errors
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
