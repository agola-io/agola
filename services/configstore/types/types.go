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

type ObjectKind string

const (
	ObjectKindUser         ObjectKind = "user"
	ObjectKindOrg          ObjectKind = "org"
	ObjectKindOrgMember    ObjectKind = "orgmember"
	ObjectKindProjectGroup ObjectKind = "projectgroup"
	ObjectKindProject      ObjectKind = "project"
	ObjectKindRemoteSource ObjectKind = "remotesource"
	ObjectKindSecret       ObjectKind = "secret"
	ObjectKindVariable     ObjectKind = "variable"
)

type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibilityPrivate Visibility = "private"
)

func IsValidVisibility(v Visibility) bool {
	switch v {
	case VisibilityPublic:
	case VisibilityPrivate:
	default:
		return false
	}
	return true
}

type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleMember MemberRole = "member"
)

func IsValidMemberRole(r MemberRole) bool {
	switch r {
	case MemberRoleOwner:
	case MemberRoleMember:
	default:
		return false
	}
	return true
}

type Parent struct {
	Kind ObjectKind `json:"type,omitempty"`
	ID   string     `json:"id,omitempty"`
}
