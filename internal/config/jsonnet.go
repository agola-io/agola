// Copyright 2020 Sorint.lab
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

package config

import (
	"encoding/json"

	"agola.io/agola/internal/errors"
	"github.com/google/go-jsonnet"
)

func execJsonnet(configData []byte, configContext *ConfigContext) ([]byte, error) {
	vm := jsonnet.MakeVM()
	cj, err := json.Marshal(configContext)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal config context")
	}

	vm.TLACode("ctx", string(cj))
	out, err := vm.EvaluateSnippet("", string(configData))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to evaluate jsonnet config")
	}

	return []byte(out), nil
}
