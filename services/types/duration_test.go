// Copyright 2022s Sorint.lab
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

package types

import (
	"encoding/json"
	"testing"
	"time"

	"gotest.tools/assert"

	"agola.io/agola/internal/testutil"
)

func TestDurationUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name         string
		expected     Duration
		jsonDuration string
	}{
		{
			name:         "test duration string",
			expected:     Duration{10 * time.Second},
			jsonDuration: `{"duration": "10s"}`,
		},
		{
			name:         "test duration nanoseconds",
			expected:     Duration{20 * time.Second},
			jsonDuration: `{"duration": 20000000000}`,
		},
	}

	for _, tt := range tests {
		var result testDurationType
		err := json.Unmarshal([]byte(tt.jsonDuration), &result)
		testutil.NilError(t, err)

		assert.DeepEqual(t, result.Duration, tt.expected)
	}
}

func TestDurationMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		duration testDurationType
	}{
		{
			name:     "test duration string",
			expected: `{"Duration":"10s"}`,
			duration: testDurationType{Duration{10 * time.Second}},
		},
	}

	for _, tt := range tests {
		result, err := json.Marshal(tt.duration)
		testutil.NilError(t, err)

		assert.Equal(t, string(result), tt.expected)
	}
}

type testDurationType struct {
	Duration Duration
}
