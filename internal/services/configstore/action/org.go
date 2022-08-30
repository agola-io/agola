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
	"context"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

type OrgMemberResponse struct {
	User *types.User
	Role types.MemberRole
}

func orgMemberResponse(orgUser *db.OrgUser) *OrgMemberResponse {
	return &OrgMemberResponse{
		User: orgUser.User,
		Role: orgUser.Role,
	}
}

func (h *ActionHandler) GetOrgMembers(ctx context.Context, orgRef string) ([]*OrgMemberResponse, error) {
	var orgUsers []*db.OrgUser
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		org, err := h.d.GetOrg(tx, orgRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if org == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("org %q doesn't exist", orgRef))
		}

		orgUsers, err = h.d.GetOrgUsers(tx, org.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := make([]*OrgMemberResponse, len(orgUsers))
	for i, orgUser := range orgUsers {
		res[i] = orgMemberResponse(orgUser)
	}

	return res, nil
}

type CreateOrgRequest struct {
	Name          string
	Visibility    types.Visibility
	CreatorUserID string
}

func (h *ActionHandler) CreateOrg(ctx context.Context, req *CreateOrgRequest) (*types.Organization, error) {
	if req.Name == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("organization name required"))
	}
	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid organization name %q", req.Name))
	}
	if !types.IsValidVisibility(req.Visibility) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid organization visibility"))
	}

	var org *types.Organization
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// check duplicate org name
		o, err := h.d.GetOrgByName(tx, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if o != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("org %q already exists", o.Name))
		}

		if req.CreatorUserID != "" {
			user, err := h.d.GetUser(tx, req.CreatorUserID)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("creator user %q doesn't exist", req.CreatorUserID))
			}
		}

		org = types.NewOrganization()
		org.Name = req.Name
		org.Visibility = req.Visibility
		org.CreatorUserID = req.CreatorUserID

		if err := h.d.InsertOrganization(tx, org); err != nil {
			return errors.WithStack(err)
		}

		if org.CreatorUserID != "" {
			// add the creator as org member with role owner
			orgmember := types.NewOrganizationMember()
			orgmember.OrganizationID = org.ID
			orgmember.UserID = org.CreatorUserID
			orgmember.MemberRole = types.MemberRoleOwner

			if err := h.d.InsertOrganizationMember(tx, orgmember); err != nil {
				return errors.WithStack(err)
			}
		}

		// create root org project group
		pg := types.NewProjectGroup()
		// use same org visibility
		pg.Visibility = org.Visibility
		pg.Parent = types.Parent{
			Kind: types.ObjectKindOrg,
			ID:   org.ID,
		}

		if err := h.d.InsertProjectGroup(tx, pg); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return org, errors.WithStack(err)
}

func (h *ActionHandler) DeleteOrg(ctx context.Context, orgRef string) error {
	var org *types.Organization

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// check org existance
		org, err = h.d.GetOrgByName(tx, orgRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if org == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("org %q doesn't exist", orgRef))
		}

		// TODO(sgotti) delete all project groups, projects etc...
		if err := h.d.DeleteOrganization(tx, org.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}

// AddOrgMember add/updates an org member.
// TODO(sgotti) handle invitation when implemented
func (h *ActionHandler) AddOrgMember(ctx context.Context, orgRef, userRef string, role types.MemberRole) (*types.OrganizationMember, error) {
	if !types.IsValidMemberRole(role) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid role %q", role))
	}

	var orgmember *types.OrganizationMember
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check existing org
		org, err := h.d.GetOrg(tx, orgRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if org == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("org %q doesn't exists", orgRef))
		}
		// check existing user
		user, err := h.d.GetUser(tx, userRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if user == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q doesn't exists", userRef))
		}

		// fetch org member if it already exist
		orgmember, err = h.d.GetOrgMemberByOrgUserID(tx, org.ID, user.ID)
		if err != nil {
			return errors.WithStack(err)
		}

		// update if role changed
		if orgmember != nil {
			if orgmember.MemberRole == role {
				return nil
			}
			orgmember.MemberRole = role
		} else {
			orgmember = types.NewOrganizationMember()
			orgmember.OrganizationID = org.ID
			orgmember.UserID = user.ID
			orgmember.MemberRole = role
		}

		if err := h.d.InsertOrganizationMember(tx, orgmember); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgmember, errors.WithStack(err)
}

// RemoveOrgMember removes an org member.
func (h *ActionHandler) RemoveOrgMember(ctx context.Context, orgRef, userRef string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check existing org
		org, err := h.d.GetOrg(tx, orgRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if org == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("org %q doesn't exists", orgRef))
		}
		// check existing user
		user, err := h.d.GetUser(tx, userRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if user == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q doesn't exists", userRef))
		}

		// check that org member exists
		orgmember, err := h.d.GetOrgMemberByOrgUserID(tx, org.ID, user.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if orgmember == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("orgmember for org %q, user %q doesn't exists", orgRef, userRef))
		}

		if err := h.d.DeleteOrganizationMember(tx, orgmember.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
