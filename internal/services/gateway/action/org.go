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

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetOrg(ctx context.Context, orgRef string) (*types.Organization, error) {
	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return org, nil
}

type GetOrgsRequest struct {
	Start string
	Limit int
	Asc   bool
}

func (h *ActionHandler) GetOrgs(ctx context.Context, req *GetOrgsRequest) ([]*types.Organization, error) {
	orgs, resp, err := h.configstoreClient.GetOrgs(ctx, req.Start, req.Limit, req.Asc)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return orgs, nil
}

type OrgMembersResponse struct {
	Organization *types.Organization
	Members      []*OrgMemberResponse
}

type OrgMemberResponse struct {
	User *types.User
	Role types.MemberRole
}

func (h *ActionHandler) GetOrgMembers(ctx context.Context, orgRef string) (*OrgMembersResponse, error) {
	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	orgMembers, resp, err := h.configstoreClient.GetOrgMembers(ctx, orgRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	res := &OrgMembersResponse{
		Organization: org,
		Members:      make([]*OrgMemberResponse, len(orgMembers)),
	}
	for i, orgMember := range orgMembers {
		res.Members[i] = &OrgMemberResponse{
			User: orgMember.User,
			Role: orgMember.Role,
		}
	}
	return res, nil
}

type CreateOrgRequest struct {
	Name       string
	Visibility types.Visibility

	CreatorUserID string
}

func (h *ActionHandler) CreateOrg(ctx context.Context, req *CreateOrgRequest) (*types.Organization, error) {
	if !h.IsUserLoggedOrAdmin(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	if req.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("organization name required"))
	}
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid organization name %q", req.Name))
	}

	org := &types.Organization{
		Name:       req.Name,
		Visibility: req.Visibility,
	}
	if req.CreatorUserID != "" {
		org.CreatorUserID = req.CreatorUserID
	}

	h.log.Infof("creating organization")
	org, resp, err := h.configstoreClient.CreateOrg(ctx, org)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Errorf("failed to create organization: %w", err))
	}
	h.log.Infof("organization %s created, ID: %s", org.Name, org.ID)

	return org, nil
}

func (h *ActionHandler) DeleteOrg(ctx context.Context, orgRef string) error {
	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return ErrFromRemote(resp, err)
	}

	isOrgOwner, err := h.IsOrgOwner(ctx, org.ID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isOrgOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.DeleteOrg(ctx, orgRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Errorf("failed to delete org: %w", err))
	}
	return nil
}

type AddOrgMemberResponse struct {
	OrganizationMember *types.OrganizationMember
	Org                *types.Organization
	User               *types.User
}

func (h *ActionHandler) AddOrgMember(ctx context.Context, orgRef, userRef string, role types.MemberRole) (*AddOrgMemberResponse, error) {
	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	isOrgOwner, err := h.IsOrgOwner(ctx, org.ID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isOrgOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	orgmember, resp, err := h.configstoreClient.AddOrgMember(ctx, orgRef, userRef, role)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Errorf("failed to add/update organization member: %w", err))
	}

	return &AddOrgMemberResponse{
		OrganizationMember: orgmember,
		Org:                org,
		User:               user,
	}, nil
}

func (h *ActionHandler) RemoveOrgMember(ctx context.Context, orgRef, userRef string) error {
	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return ErrFromRemote(resp, err)
	}

	isOrgOwner, err := h.IsOrgOwner(ctx, org.ID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isOrgOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.RemoveOrgMember(ctx, orgRef, userRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Errorf("failed to remove organization member: %w", err))
	}

	return nil
}
