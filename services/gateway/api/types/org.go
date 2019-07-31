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

type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleMember MemberRole = "member"
)

type CreateOrgRequest struct {
	Name       string     `json:"name"`
	Visibility Visibility `json:"visibility"`
}

type OrgResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Visibility Visibility `json:"visibility,omitempty"`
}

type OrgMembersResponse struct {
	Organization *OrgResponse         `json:"organization"`
	Members      []*OrgMemberResponse `json:"members"`
}

type OrgMemberResponse struct {
	User *UserResponse `json:"user"`
	Role MemberRole    `json:"role"`
}

type AddOrgMemberResponse struct {
	Organization *OrgResponse `json:"organization"`
	OrgMemberResponse
}

type AddOrgMemberRequest struct {
	Role MemberRole `json:"role"`
}
