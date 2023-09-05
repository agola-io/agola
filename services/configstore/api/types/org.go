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

package types

import (
	"agola.io/agola/services/configstore/types"
)

type CreateOrgRequest struct {
	Name          string
	Visibility    types.Visibility
	CreatorUserID string
}

type AddOrgMemberRequest struct {
	Role types.MemberRole
}

type OrgsResponse struct {
	Orgs        []*types.Organization
	HasMoreData bool
}

type OrgMemberResponse struct {
	User *types.User
	Role types.MemberRole
}

type OrgMembersResponse struct {
	OrgMembers  []*OrgMemberResponse
	HasMoreData bool
}

type UpdateOrgRequest struct {
	Visibility types.Visibility
}
