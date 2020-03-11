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
	"bytes"
	"encoding/json"
	"fmt"

	"go.starlark.net/starlark"
	errors "golang.org/x/xerrors"
)

func starlarkArgs(cc *ConfigContext) (starlark.Tuple, error) {
	d := &starlark.Dict{}
	if err := d.SetKey(starlark.String("ref_type"), starlark.String(cc.RefType)); err != nil {
		return nil, err
	}
	if err := d.SetKey(starlark.String("ref"), starlark.String(cc.Ref)); err != nil {
		return nil, err
	}
	if err := d.SetKey(starlark.String("branch"), starlark.String(cc.Branch)); err != nil {
		return nil, err
	}
	if err := d.SetKey(starlark.String("tag"), starlark.String(cc.Tag)); err != nil {
		return nil, err
	}
	if err := d.SetKey(starlark.String("pull_request_id"), starlark.String(cc.PullRequestID)); err != nil {
		return nil, err
	}
	if err := d.SetKey(starlark.String("commit_sha"), starlark.String(cc.CommitSHA)); err != nil {
		return nil, err
	}

	return []starlark.Value{d}, nil
}

// based on (not existing anymore) function provided in
// https://github.com/google/starlark-go/blob/6fffce7528ee0fce17d72a4abe2919f464225968/starlarkstruct/struct.go#L325
// with changes to use go json marshalling functions
func starlarkJSON(out *bytes.Buffer, v starlark.Value) error {
	switch v := v.(type) {
	case starlark.NoneType:
		out.WriteString("null")
	case starlark.Bool:
		fmt.Fprintf(out, "%t", v)
	case starlark.Int:
		data, err := json.Marshal(v.BigInt())
		if err != nil {
			return err
		}
		out.Write(data)
	case starlark.Float:
		data, err := json.Marshal(float64(v))
		if err != nil {
			return err
		}
		out.Write(data)
	case starlark.String:
		// we have to use a json Encoder to disable noisy html
		// escaping. But the encoder appends a final \n so we
		// also should remove it.
		data := &bytes.Buffer{}
		e := json.NewEncoder(data)
		e.SetEscapeHTML(false)
		if err := e.Encode(string(v)); err != nil {
			return err
		}
		// remove final \n introduced by the encoder
		out.Write(bytes.TrimSuffix(data.Bytes(), []byte("\n")))
	case starlark.Indexable: // Tuple, List
		out.WriteByte('[')
		for i, n := 0, starlark.Len(v); i < n; i++ {
			if i > 0 {
				out.WriteString(", ")
			}
			if err := starlarkJSON(out, v.Index(i)); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case *starlark.Dict:
		out.WriteByte('{')
		for i, item := range v.Items() {
			if i > 0 {
				out.WriteString(", ")
			}
			if _, ok := item[0].(starlark.String); !ok {
				return fmt.Errorf("cannot convert non-string dict key to JSON")
			}
			if err := starlarkJSON(out, item[0]); err != nil {
				return err
			}
			out.WriteString(": ")
			if err := starlarkJSON(out, item[1]); err != nil {
				return err
			}
		}
		out.WriteByte('}')

	default:
		return fmt.Errorf("cannot convert starlark type %q to JSON", v.Type())
	}
	return nil
}

func execStarlark(configData []byte, configContext *ConfigContext) ([]byte, error) {
	thread := &starlark.Thread{
		Name: "agola-starlark",
		// TODO(sgotti) redirect print to a logger?
		Print: func(_ *starlark.Thread, msg string) {},
	}
	globals, err := starlark.ExecFile(thread, "config.star", configData, nil)
	if err != nil {
		return nil, err
	}

	// we require a main function that will be called wiht one
	// arguments containing the config context
	mainVal, ok := globals["main"]
	if !ok {
		return nil, errors.Errorf("no main function in starlark config")
	}
	main, ok := mainVal.(starlark.Callable)
	if !ok {
		return nil, errors.Errorf("main in starlark config is not a function")
	}
	args, err := starlarkArgs(configContext)
	if err != nil {
		return nil, errors.Errorf("cannot create startlark arguments: %w", err)
	}
	mainVal, err = starlark.Call(thread, main, args, nil)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	switch v := mainVal.(type) {
	case *starlark.Dict:
		if err := starlarkJSON(buf, v); err != nil {
			return nil, err
		}
	default:
		return nil, errors.Errorf("wrong starlark output, must be a dict")
	}

	return buf.Bytes(), nil
}
