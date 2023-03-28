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
	"github.com/rs/zerolog"

	scommon "agola.io/agola/internal/services/common"
	csclient "agola.io/agola/services/configstore/client"
	rsclient "agola.io/agola/services/runservice/client"
)

type ActionHandler struct {
	log                          zerolog.Logger
	sd                           *scommon.TokenSigningData
	sc                           *scommon.CookieSigningData
	configstoreClient            *csclient.Client
	runserviceClient             *rsclient.Client
	agolaID                      string
	apiExposedURL                string
	webExposedURL                string
	unsecureCookies              bool
	organizationMemberAddingMode OrganizationMemberAddingMode
}

type OrganizationMemberAddingMode string

const (
	OrganizationMemberAddingModeDirect     OrganizationMemberAddingMode = "direct"
	OrganizationMemberAddingModeInvitation OrganizationMemberAddingMode = "invitation"
)

func NewActionHandler(log zerolog.Logger, sd *scommon.TokenSigningData, sc *scommon.CookieSigningData, configstoreClient *csclient.Client, runserviceClient *rsclient.Client, agolaID, apiExposedURL, webExposedURL string, unsecureCookies bool, organizationMemberAddingMode OrganizationMemberAddingMode) *ActionHandler {
	return &ActionHandler{
		log:                          log,
		sd:                           sd,
		sc:                           sc,
		configstoreClient:            configstoreClient,
		runserviceClient:             runserviceClient,
		agolaID:                      agolaID,
		apiExposedURL:                apiExposedURL,
		webExposedURL:                webExposedURL,
		unsecureCookies:              unsecureCookies,
		organizationMemberAddingMode: organizationMemberAddingMode,
	}
}
