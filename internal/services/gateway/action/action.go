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

package action

import (
	"agola.io/agola/internal/services/common"
	csclient "agola.io/agola/services/configstore/client"
	rsclient "agola.io/agola/services/runservice/client"

	"github.com/rs/zerolog"
)

type ActionHandler struct {
	log               zerolog.Logger
	sd                *common.TokenSigningData
	configstoreClient *csclient.Client
	runserviceClient  *rsclient.Client
	agolaID           string
	apiExposedURL     string
	webExposedURL     string
}

func NewActionHandler(log zerolog.Logger, sd *common.TokenSigningData, configstoreClient *csclient.Client, runserviceClient *rsclient.Client, agolaID, apiExposedURL, webExposedURL string) *ActionHandler {
	return &ActionHandler{
		log:               log,
		sd:                sd,
		configstoreClient: configstoreClient,
		runserviceClient:  runserviceClient,
		agolaID:           agolaID,
		apiExposedURL:     apiExposedURL,
		webExposedURL:     webExposedURL,
	}
}
