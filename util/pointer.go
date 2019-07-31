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

import "time"

func BoolP(b bool) *bool { return &b }

func ByteP(b byte) *byte { return &b }

func StringP(s string) *string { return &s }

func IntP(i int) *int { return &i }

func Int8P(i int8) *int8 { return &i }

func Int16P(i int16) *int16 { return &i }

func Int32P(i int32) *int32 { return &i }

func Int64P(i int64) *int64 { return &i }

func UintP(u uint) *uint { return &u }

func Uint16P(u uint16) *uint16 { return &u }

func Uint32P(u uint32) *uint32 { return &u }

func Uint64P(u uint64) *uint64 { return &u }

func Uint8P(u uint8) *uint8 { return &u }

func TimeP(t time.Time) *time.Time { return &t }

func DurationP(d time.Duration) *time.Duration { return &d }
