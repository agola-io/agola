// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package action

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
	uuid "github.com/satori/go.uuid"
)

type OrgMemberResponse struct {
	User *types.User
	Role types.MemberRole
}

func orgMemberResponse(orgUser *readdb.OrgUser) *OrgMemberResponse {
	return &OrgMemberResponse{
		User: orgUser.User,
		Role: orgUser.Role,
	}
}

func (h *ActionHandler) GetOrgMembers(ctx context.Context, orgRef string) ([]*OrgMemberResponse, error) {
	var orgUsers []*readdb.OrgUser
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		org, err := h.readDB.GetOrg(tx, orgRef)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrNotFound(errors.Errorf("org %q doesn't exist", orgRef))
		}

		orgUsers, err = h.readDB.GetOrgUsers(tx, org.ID)
		return err
	})
	if err != nil {
		return nil, err
	}

	res := make([]*OrgMemberResponse, len(orgUsers))
	for i, orgUser := range orgUsers {
		res[i] = orgMemberResponse(orgUser)
	}

	return res, nil
}

func (h *ActionHandler) CreateOrg(ctx context.Context, org *types.Organization) (*types.Organization, error) {
	if org.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("organization name required"))
	}
	if !util.ValidateName(org.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid organization name %q", org.Name))
	}
	if !types.IsValidVisibility(org.Visibility) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid organization visibility"))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the org name
	cgNames := []string{util.EncodeSha256Hex("orgname-" + org.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate org name
		o, err := h.readDB.GetOrgByName(tx, org.Name)
		if err != nil {
			return err
		}
		if o != nil {
			return util.NewErrBadRequest(errors.Errorf("org %q already exists", o.Name))
		}

		if org.CreatorUserID != "" {
			user, err := h.readDB.GetUser(tx, org.CreatorUserID)
			if err != nil {
				return err
			}
			if user == nil {
				return util.NewErrBadRequest(errors.Errorf("creator user %q doesn't exist", org.CreatorUserID))
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	actions := []*datamanager.Action{}

	org.ID = uuid.NewV4().String()
	org.CreatedAt = time.Now()
	orgj, err := json.Marshal(org)
	if err != nil {
		return nil, errors.Errorf("failed to marshal org: %w", err)
	}
	actions = append(actions, &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
		DataType:   string(types.ConfigTypeOrg),
		ID:         org.ID,
		Data:       orgj,
	})

	if org.CreatorUserID != "" {
		// add the creator as org member with role owner
		orgmember := &types.OrganizationMember{
			ID:             uuid.NewV4().String(),
			OrganizationID: org.ID,
			UserID:         org.CreatorUserID,
			MemberRole:     types.MemberRoleOwner,
		}
		orgmemberj, err := json.Marshal(orgmember)
		if err != nil {
			return nil, errors.Errorf("failed to marshal project group: %w", err)
		}
		actions = append(actions, &datamanager.Action{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeOrgMember),
			ID:         orgmember.ID,
			Data:       orgmemberj,
		})
	}

	// create root org project group
	pg := &types.ProjectGroup{
		ID: uuid.NewV4().String(),
		// use same org visibility
		Visibility: org.Visibility,
		Parent: types.Parent{
			Type: types.ConfigTypeOrg,
			ID:   org.ID,
		},
	}
	pgj, err := json.Marshal(pg)
	if err != nil {
		return nil, errors.Errorf("failed to marshal project group: %w", err)
	}
	actions = append(actions, &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
		DataType:   string(types.ConfigTypeProjectGroup),
		ID:         pg.ID,
		Data:       pgj,
	})

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return org, err
}

func (h *ActionHandler) DeleteOrg(ctx context.Context, orgRef string) error {
	var org *types.Organization
	var projects []*types.Project

	var cgt *datamanager.ChangeGroupsUpdateToken
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check org existance
		org, err = h.readDB.GetOrgByName(tx, orgRef)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrBadRequest(errors.Errorf("org %q doesn't exist", orgRef))
		}

		// changegroup is the org id
		cgNames := []string{util.EncodeSha256Hex("orgid-" + org.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// TODO(sgotti) delete all project groups, projects etc...
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeOrg),
			ID:         org.ID,
		},
	}
	// delete all org projects
	for _, project := range projects {
		actions = append(actions, &datamanager.Action{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		})
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}

// AddOrgMember add/updates an org member.
// TODO(sgotti) handle invitation when implemented
func (h *ActionHandler) AddOrgMember(ctx context.Context, orgRef, userRef string, role types.MemberRole) (*types.OrganizationMember, error) {
	if !types.IsValidMemberRole(role) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid role %q", role))
	}

	var org *types.Organization
	var user *types.User
	var orgmember *types.OrganizationMember
	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check existing org
		org, err = h.readDB.GetOrg(tx, orgRef)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrBadRequest(errors.Errorf("org %q doesn't exists", orgRef))
		}
		// check existing user
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exists", userRef))
		}

		// fetch org member if it already exist
		orgmember, err = h.readDB.GetOrgMemberByOrgUserID(tx, org.ID, user.ID)
		if err != nil {
			return err
		}

		cgNames := []string{util.EncodeSha256Hex(fmt.Sprintf("orgmember-%s-%s", org.ID, user.ID))}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// update if role changed
	if orgmember != nil {
		if orgmember.MemberRole == role {
			return orgmember, nil
		}
		orgmember.MemberRole = role
	} else {
		orgmember = &types.OrganizationMember{
			ID:             uuid.NewV4().String(),
			OrganizationID: org.ID,
			UserID:         user.ID,
			MemberRole:     role,
		}
	}

	actions := []*datamanager.Action{}
	orgmemberj, err := json.Marshal(orgmember)
	if err != nil {
		return nil, errors.Errorf("failed to marshal project group: %w", err)
	}
	actions = append(actions, &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
		DataType:   string(types.ConfigTypeOrgMember),
		ID:         orgmember.ID,
		Data:       orgmemberj,
	})

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return orgmember, err
}

// RemoveOrgMember removes an org member.
func (h *ActionHandler) RemoveOrgMember(ctx context.Context, orgRef, userRef string) error {
	var org *types.Organization
	var user *types.User
	var orgmember *types.OrganizationMember
	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check existing org
		org, err = h.readDB.GetOrg(tx, orgRef)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrBadRequest(errors.Errorf("org %q doesn't exists", orgRef))
		}
		// check existing user
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exists", userRef))
		}

		// check that org member exists
		orgmember, err = h.readDB.GetOrgMemberByOrgUserID(tx, org.ID, user.ID)
		if err != nil {
			return err
		}
		if orgmember == nil {
			return util.NewErrBadRequest(errors.Errorf("orgmember for org %q, user %q doesn't exists", orgRef, userRef))
		}

		cgNames := []string{util.EncodeSha256Hex(fmt.Sprintf("orgmember-%s-%s", org.ID, user.ID))}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	actions := []*datamanager.Action{}
	actions = append(actions, &datamanager.Action{
		ActionType: datamanager.ActionTypeDelete,
		DataType:   string(types.ConfigTypeOrgMember),
		ID:         orgmember.ID,
	})

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
