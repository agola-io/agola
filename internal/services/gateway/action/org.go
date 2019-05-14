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

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
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
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create organization"))
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
		return errors.Wrapf(err, "failed to determine ownership")
	}
	if !isOrgOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.DeleteOrg(ctx, orgRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to delete org"))
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
		return nil, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isOrgOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	orgmember, resp, err := h.configstoreClient.AddOrgMember(ctx, orgRef, userRef, role)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to add/update organization member"))
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
		return errors.Wrapf(err, "failed to determine ownership")
	}
	if !isOrgOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.RemoveOrgMember(ctx, orgRef, userRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to remove organization member"))
	}

	return nil
}
