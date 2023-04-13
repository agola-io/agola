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
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type Organization struct {
	sqlg.ObjectMeta

	Name string `json:"name,omitempty"`

	Visibility Visibility `json:"visibility,omitempty"`

	// CreatorUserID is the user id that created the organization. It could be empty
	// if the org was created by using the admin user or the user has been removed.
	CreatorUserID string `json:"creator_user_id,omitempty"`
}

func NewOrganization(tx *sql.Tx) *Organization {
	return &Organization{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}

type OrganizationMember struct {
	sqlg.ObjectMeta

	OrganizationID string `json:"organization_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`

	MemberRole MemberRole `json:"member_role,omitempty"`
}

func NewOrganizationMember(tx *sql.Tx) *OrganizationMember {
	return &OrganizationMember{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
