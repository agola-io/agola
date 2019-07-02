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

package handlers

import (
	"bytes"
	"net/http"
	"strings"
	"text/template"

	"agola.io/agola/webbundle"

	assetfs "github.com/elazarl/go-bindata-assetfs"
)

// TODO(sgotti) now the test web ui directly calls the run api url, but this is
// temporary and all requests should pass from the gateway

const configTplText = `
const CONFIG = {
  API_URL: '{{.ApiURL}}',
  API_BASE_PATH: '{{.ApiBasePath}}',
}

window.CONFIG = CONFIG
`

func NewWebBundleHandlerFunc(gatewayURL string) func(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	configTpl, err := template.New("config").Parse(configTplText)
	if err != nil {
		panic(err)
	}

	configTplData := struct {
		ApiURL      string
		ApiBasePath string
	}{
		gatewayURL,
		"/api/v1alpha",
	}
	if err := configTpl.Execute(&buf, configTplData); err != nil {
		panic(err)
	}

	config := buf.Bytes()

	return func(w http.ResponseWriter, r *http.Request) {
		// Setup serving of bundled webapp from the root path, registered after api
		// handlers or it'll match all the requested paths
		fileServerHandler := http.FileServer(&assetfs.AssetFS{
			Asset:     webbundle.Asset,
			AssetDir:  webbundle.AssetDir,
			AssetInfo: webbundle.AssetInfo,
		})

		// config.js is the external webapp config file not provided by the
		// asset and not needed when served from the api server
		if r.URL.Path == "/config.js" {
			_, err := w.Write(config)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
			}
			return
		}

		// check if the required file is available in the webapp asset and serve it
		if _, err := webbundle.Asset(r.URL.Path[1:]); err == nil {
			fileServerHandler.ServeHTTP(w, r)
			return
		}

		// skip /api requests
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "", http.StatusNotFound)
			return
		}

		// Fallback to index.html for every other page. Required for the SPA since
		// on browser reload it'll ask the current app url but we have to
		// provide the index.html
		r.URL.Path = "/"
		fileServerHandler.ServeHTTP(w, r)
	}
}
