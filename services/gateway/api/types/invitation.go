// Copyright 2022 Sorint.lab
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
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type CreateOrgInvitationRequest struct {
	UserRef string           `json:"user_ref"`
	Role    types.MemberRole `json:"role"`
}

type OrgInvitationResponse struct {
	ID               string `json:"id"`
	UserID           string `json:"user_ref"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
}

type OrgInvitationActionRequest struct {
	Action csapitypes.OrgInvitationActionType `json:"action_type"`
}
