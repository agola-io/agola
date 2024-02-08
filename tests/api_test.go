package tests

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	rstypes "agola.io/agola/services/runservice/types"
)

func TestGetRemoteSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir)
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	remoteSources := []*gwapitypes.RemoteSourceResponse{}
	for i := 1; i < 10; i++ {
		remoteSource, _, err := gwClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
			Name:                fmt.Sprintf("rs%d", i),
			APIURL:              "http://apiurl",
			Type:                "gitea",
			AuthType:            "password",
			SkipSSHHostKeyCheck: true,
		})
		testutil.NilError(t, err)

		remoteSources = append(remoteSources, remoteSource)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       gwapitypes.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "get remote sources with limit = 0, no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "get remote sources with limit = 0",
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get remote sources with limit less than results length",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get remote sources with limit greater than results length",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get remote sources with limit = 0, sortDirection desc",
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get remote sources with limit less than results length, sortDirection desc",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get remote sources with limit greater than results length, sortDirection desc",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedRemoteSources := append([]*gwapitypes.RemoteSourceResponse{}, remoteSources...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedRemoteSources)-1; i < j; i, j = i+1, j-1 {
					expectedRemoteSources[i], expectedRemoteSources[j] = expectedRemoteSources[j], expectedRemoteSources[i]
				}
			}

			respAllRemoteSources := []*gwapitypes.RemoteSourceResponse{}
			sortDirection := tt.sortDirection
			callsNumber := 0
			var cursor string

			for {
				respRemoteSources, res, err := gwClient.GetRemoteSources(ctx, &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllRemoteSources = append(respAllRemoteSources, respRemoteSources...)

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
			}

			assert.DeepEqual(t, expectedRemoteSources, respAllRemoteSources)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetOrg(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	// create users
	_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
	testutil.NilError(t, err)

	tokenUser03, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser03, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser03 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser03.Token)

	// create public org
	pubOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create private org
	privOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// add user02 as member of priv org
	_, _, err = gwClientUser01.AddOrgMember(ctx, privOrg.ID, agolaUser02, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	tests := []struct {
		name   string
		client *gwclient.Client
		org    *gwapitypes.OrgResponse
		err    string
	}{
		{
			name:   "user owner get pub org",
			client: gwClientUser01,
			org:    pubOrg,
		},
		{
			name:   "user member get pub org",
			client: gwClientUser02,
			org:    pubOrg,
		},
		{
			name:   "user not member get pub org",
			client: gwClientUser03,
			org:    pubOrg,
		},
		{
			name:   "user owner get priv org",
			client: gwClientUser01,
			org:    privOrg,
		},
		{
			name:   "user member get priv org",
			client: gwClientUser02,
			org:    privOrg,
		},
		{
			name:   "user not member get priv org",
			client: gwClientUser03,
			org:    privOrg,
			err:    remoteErrorNotExist,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			org, _, err := tt.client.GetOrg(ctx, tt.org.ID)

			if tt.err != "" {
				assert.Error(t, err, tt.err)
			} else {
				testutil.NilError(t, err)

				assert.DeepEqual(t, tt.org, org)
			}
		})
	}
}

func TestUpdateOrganization(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	//create user01 and user02
	_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

	//create org
	org, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	//user owner update org
	expectedOrgResponse := &gwapitypes.OrgResponse{ID: org.ID, Name: agolaOrg01, Visibility: gwapitypes.VisibilityPrivate}

	visibility := gwapitypes.VisibilityPrivate
	updatedOrg, _, err := gwClientUser01.UpdateOrg(ctx, agolaOrg01, &gwapitypes.UpdateOrgRequest{Visibility: &visibility})
	testutil.NilError(t, err)

	assert.DeepEqual(t, updatedOrg, expectedOrgResponse)

	org, _, err = gwClientUser01.GetOrg(ctx, agolaOrg01)
	testutil.NilError(t, err)

	assert.DeepEqual(t, expectedOrgResponse, org)

	//user member update org
	visibility = gwapitypes.VisibilityPrivate
	_, _, err = gwClientUser02.UpdateOrg(ctx, agolaOrg01, &gwapitypes.UpdateOrgRequest{Visibility: &visibility})
	expectedErr := remoteErrorForbidden
	assert.Error(t, err, expectedErr)

	org, _, err = gwClientUser01.GetOrg(ctx, agolaOrg01)
	testutil.NilError(t, err)

	assert.DeepEqual(t, expectedOrgResponse, org)
}

func TestOrgInvitation(t *testing.T) {
	t.Parallel()

	type testOrgInvitationConfig struct {
		sc             *setupContext
		tokenUser01    string
		tokenUser02    string
		gwAdminClient  *gwclient.Client
		gwClientUser01 *gwclient.Client
		gwClientUser02 *gwclient.Client
	}

	tests := []struct {
		name                 string
		orgInvitationEnabled bool
		f                    func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig)
	}{
		{
			name:                 "create org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				invitation, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				i, _, err := tc.gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				testutil.NilError(t, err)

				assert.DeepEqual(t, i, invitation)
			},
		},
		{
			name:                 "user org invitation creation with already existing invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorInternal
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "get user invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				invitation, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, _, err = tc.gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				userInvitations, _, err := tc.gwClientUser02.GetUserOrgInvitations(ctx)
				expectedUserInvitations := []*gwapitypes.OrgInvitationResponse{invitation}
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(userInvitations, 1))
				assert.DeepEqual(t, expectedUserInvitations, userInvitations)
			},
		},
		{
			name:                 "user not owner create invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser02.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser01, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorForbidden
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user reject invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Reject})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser02.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user owner delete invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwClientUser01.DeleteOrgInvitation(ctx, agolaOrg01, agolaUser02)
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user accept invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser02.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)

				org01Members, _, err := tc.gwClientUser01.GetOrgMembers(ctx, agolaOrg01, nil)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(org01Members.Members, 2))
			},
		},
		{
			name:                 "create invitation org not exists",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg02, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "create invitation user already org member",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorInternal
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "create invitation user doesn't exist",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user deletion with existing org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwAdminClient.DeleteUser(ctx, agolaUser02)
				testutil.NilError(t, err)

				org01Invitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(org01Invitations, 0))
			},
		},
		{
			name:                 "org deletion with existing org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, err = tc.gwClientUser01.DeleteOrg(ctx, agolaOrg01)
				testutil.NilError(t, err)

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)
				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
		{
			name:                 "create org invitation and accept after invitations disabled",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				// disable invitations in agola config
				tc.sc.config.Gateway.OrganizationMemberAddingMode = config.OrganizationMemberAddingModeInvitation
				err = tc.sc.restartAgola()
				testutil.NilError(t, err)

				gwClientUser01 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser01)
				gwClientUser02 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser02)

				_, err = gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				testutil.NilError(t, err)

				_, _, err = gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := remoteErrorNotExist
				assert.Error(t, err, expectedErr)

				orgMembers, _, err := gwClientUser01.GetOrgMembers(ctx, agolaOrg01, nil)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgMembers.Members, 2))
			},
		},
		{
			name:                 "user owner create org invitation with invitations disabled",
			orgInvitationEnabled: false,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := remoteErrorBadRequest
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user owner add org member directly with invitations enabled",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				expectedErr := remoteErrorBadRequest
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name:                 "user owner add org member with existing org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				// disable invitations in agola config
				tc.sc.config.Gateway.OrganizationMemberAddingMode = config.OrganizationMemberAddingModeDirect
				err = tc.sc.restartAgola()
				testutil.NilError(t, err)

				gwClientUser01 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser01)

				_, _, err = gwClientUser01.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				testutil.NilError(t, err)

				orgInvitations, _, err := gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
		{
			name:                 "user admin add org member directly with existing org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, _, err = tc.gwAdminClient.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				testutil.NilError(t, err)

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
		{
			name:                 "user owner get org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				testutil.NilError(t, err)

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 2))

				_, _, err = tc.gwClientUser02.GetOrgInvitations(ctx, agolaOrg01)
				expectedErr := remoteErrorForbidden
				assert.Error(t, err, expectedErr)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var sc *setupContext
			if tt.orgInvitationEnabled {
				sc = setup(ctx, t, dir, withOrganizationMemberAddingMode(config.OrganizationMemberAddingModeInvitation))
			} else {
				sc = setup(ctx, t, dir)
			}
			defer sc.stop()

			gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

			_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			testutil.NilError(t, err)

			tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
			testutil.NilError(t, err)

			_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
			testutil.NilError(t, err)

			tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
			testutil.NilError(t, err)

			_, _, err = gwAdminClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
			testutil.NilError(t, err)

			_, _, err = gwAdminClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleOwner)
			testutil.NilError(t, err)

			gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)
			gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

			tc := &testOrgInvitationConfig{
				sc:             sc,
				tokenUser01:    tokenUser01.Token,
				tokenUser02:    tokenUser02.Token,
				gwClientUser01: gwClientUser01,
				gwClientUser02: gwClientUser02,
				gwAdminClient:  gwAdminClient,
			}

			tt.f(ctx, t, tc)
		})
	}
}

func TestGetOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir)
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)

	allOrgs := []*gwapitypes.OrgResponse{}
	publicOrgs := []*gwapitypes.OrgResponse{}
	for i := 1; i < 19; i++ {
		// mix public with private visiblity
		visibility := gwapitypes.VisibilityPublic
		if i%2 == 0 {
			visibility = gwapitypes.VisibilityPrivate
		}
		org, _, err := gwAdminClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: fmt.Sprintf("org%02d", i), Visibility: visibility})
		testutil.NilError(t, err)

		allOrgs = append(allOrgs, org)
		if visibility == gwapitypes.VisibilityPublic {
			publicOrgs = append(publicOrgs, org)
		}
	}

	tests := []struct {
		name                string
		getPublicOrgsOnly   bool
		limit               int
		sortDirection       gwapitypes.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "get public orgs with limit = 0, no sortdirection",
			getPublicOrgsOnly:   true,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public orgs with limit = 0",
			getPublicOrgsOnly:   true,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public/private orgs with limit = 0",
			getPublicOrgsOnly:   false,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public orgs with limit less than results length",
			getPublicOrgsOnly:   true,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get public orgs with limit greater than results length",
			getPublicOrgsOnly:   true,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public orgs with limit less than results length",
			getPublicOrgsOnly:   true,
			limit:               3,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 3,
		},
		{
			name:                "get public/private orgs with limit less than results length",
			getPublicOrgsOnly:   false,
			limit:               3,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 6,
		},
		{
			name:                "get public orgs with limit = 0, sortDirection desc",
			getPublicOrgsOnly:   true,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public/private orgs with limit = 0, sortDirection desc",
			getPublicOrgsOnly:   false,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public orgs with limit less than results length, sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get public orgs with limit greater than results length, sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get public orgs with limit less than results length, sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               3,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 3,
		},
		{
			name:                "get public/private orgs with limit less than results length, sortDirection desc",
			getPublicOrgsOnly:   false,
			limit:               3,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 6,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// populate the expected orgs and client
			var expectedOrgs []*gwapitypes.OrgResponse
			var client *gwclient.Client
			if tt.getPublicOrgsOnly {
				expectedOrgs = append(expectedOrgs, publicOrgs...)
				client = gwUser01Client
			} else {
				expectedOrgs = append(expectedOrgs, allOrgs...)
				client = gwAdminClient
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedOrgs)-1; i < j; i, j = i+1, j-1 {
					expectedOrgs[i], expectedOrgs[j] = expectedOrgs[j], expectedOrgs[i]
				}
			}

			respAllOrgs := []*gwapitypes.OrgResponse{}
			sortDirection := tt.sortDirection
			callsNumber := 0
			var cursor string

			for {
				respOrgs, res, err := client.GetOrgs(ctx, &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllOrgs = append(respAllOrgs, respOrgs...)

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
			}

			assert.DeepEqual(t, expectedOrgs, respAllOrgs)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetOrgMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	createLinkedAccount(ctx, t, sc.gitea, sc.config)
	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	for i := 1; i < 10; i++ {
		_, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: fmt.Sprintf("orguser%d", i)})
		testutil.NilError(t, err)
	}

	org, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	allOrgMembers := []*gwapitypes.OrgMemberResponse{}
	for i := 1; i < 10; i++ {
		orgMember, _, err := gwClient.AddOrgMember(ctx, agolaOrg01, fmt.Sprintf("orguser%d", i), gwapitypes.MemberRoleMember)
		testutil.NilError(t, err)

		allOrgMembers = append(allOrgMembers, &orgMember.OrgMemberResponse)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       gwapitypes.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "get org members with limit = 0, no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "get org members with limit = 0",
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get org members with limit less than results length",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get org members with limit greater than results length",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get org members with limit = 0, sortDirection desc",
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get org members with limit less than results length, sortDirection desc",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get org members with limit greater than results length, sortDirection desc",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedOrgMembers := append([]*gwapitypes.OrgMemberResponse{}, allOrgMembers...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedOrgMembers)-1; i < j; i, j = i+1, j-1 {
					expectedOrgMembers[i], expectedOrgMembers[j] = expectedOrgMembers[j], expectedOrgMembers[i]
				}
			}

			respAllOrgMembers := []*gwapitypes.OrgMemberResponse{}
			sortDirection := tt.sortDirection
			callsNumber := 0
			var cursor string

			for {
				respOrgMembers, res, err := gwClient.GetOrgMembers(ctx, org.ID, &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllOrgMembers = append(respAllOrgMembers, respOrgMembers.Members...)

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
			}

			assert.DeepEqual(t, expectedOrgMembers, respAllOrgMembers)
			assert.Assert(t, cmp.Equal(tt.expectedCallsNumber, callsNumber))
		})
	}
}

func TestGetUserOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	createLinkedAccount(ctx, t, sc.gitea, sc.config)
	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: "orguser01"})
	testutil.NilError(t, err)

	orgs := []*gwapitypes.OrgResponse{}
	for i := 1; i < 10; i++ {
		org, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: fmt.Sprintf("org%d", i), Visibility: gwapitypes.VisibilityPublic})
		testutil.NilError(t, err)

		orgs = append(orgs, org)
	}

	for _, org := range orgs {
		_, _, err := gwClient.AddOrgMember(ctx, org.ID, user.ID, gwapitypes.MemberRoleMember)
		testutil.NilError(t, err)
	}

	tokenUser, _, err := gwClient.CreateUserToken(ctx, user.ID, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser.Token)

	tests := []struct {
		name                string
		limit               int
		sortDirection       gwapitypes.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "get user orgs with limit = 0, no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "get user orgs with limit = 0",
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get user orgs with limit less than results length",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get user orgs with limit greater than results length",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get user orgs with limit = 0, sortDirection desc",
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get user orgs with limit less than results length, sortDirection desc",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get user orgs with limit greater than results length, sortDirection desc",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedUserOrgs := append([]*gwapitypes.OrgResponse{}, orgs...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedUserOrgs)-1; i < j; i, j = i+1, j-1 {
					expectedUserOrgs[i], expectedUserOrgs[j] = expectedUserOrgs[j], expectedUserOrgs[i]
				}
			}

			respAllUserOrgs := []*gwapitypes.OrgResponse{}
			sortDirection := tt.sortDirection
			callsNumber := 0
			var cursor string

			for {
				respUserOrgs, res, err := gwClient.GetUserOrgs(ctx, &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				for _, userOrg := range respUserOrgs {
					respAllUserOrgs = append(respAllUserOrgs, userOrg.Organization)
				}

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
			}

			assert.DeepEqual(t, expectedUserOrgs, respAllUserOrgs)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestAddUpdateOrgUserMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	//test add org member role member
	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	expectedOrgMember := gwapitypes.OrgMemberResponse{
		User: &gwapitypes.UserResponse{ID: user.ID, UserName: user.UserName},
		Role: gwapitypes.MemberRoleMember,
	}

	orgMembers, _, err := gwClient.GetOrgMembers(ctx, agolaOrg01, nil)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(orgMembers.Members, 1))
	assert.DeepEqual(t, *orgMembers.Members[0], expectedOrgMember)

	//test update org member role owner
	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleOwner)
	testutil.NilError(t, err)

	expectedOrgMember.Role = gwapitypes.MemberRoleOwner

	orgMembers, _, err = gwClient.GetOrgMembers(ctx, agolaOrg01, nil)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(orgMembers.Members, 1))
	assert.DeepEqual(t, *orgMembers.Members[0], expectedOrgMember)
}

func TestUserOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")

	org01, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	org02, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg03, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	_, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, giteaUser01, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg02, giteaUser01, gwapitypes.MemberRoleOwner)
	testutil.NilError(t, err)

	gwClientNew := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	orgs, _, err := gwClientNew.GetUserOrgs(ctx, nil)
	testutil.NilError(t, err)

	expectedOrgs := []*gwapitypes.UserOrgResponse{
		{
			Organization: &gwapitypes.OrgResponse{ID: org01.ID, Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic},
			Role:         gwapitypes.MemberRoleMember,
		},

		{
			Organization: &gwapitypes.OrgResponse{ID: org02.ID, Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate},
			Role:         gwapitypes.MemberRoleOwner,
		},
	}

	assert.DeepEqual(t, expectedOrgs, orgs)
}

func TestGetUsersPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, sc *setupContext)
	}{
		{
			name: "admin get user by remoteuserid and remotesourceref",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				user, _, err := gwClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, "1", "gitea")
				testutil.NilError(t, err)

				assert.Equal(t, user.UserName, giteaUser01)
			},
		},
		{
			name: "user get user by remoteuserid and remotesourceref",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				_, user01Token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user01Token)

				_, _, err := gwClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, "1", "gitea")
				expectedErr := remoteErrorUnauthorized
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name: "admin get users",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				user01, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				testutil.NilError(t, err)

				user02, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
				testutil.NilError(t, err)

				expectedUsers := []*gwapitypes.PrivateUserResponse{
					{ID: user01.ID, UserName: user01.UserName, Tokens: []string{}, LinkedAccounts: []*gwapitypes.LinkedAccountResponse{}},
					{ID: user02.ID, UserName: user02.UserName, Tokens: []string{}, LinkedAccounts: []*gwapitypes.LinkedAccountResponse{}},
				}
				users, _, err := gwClient.GetUsers(ctx, nil)
				testutil.NilError(t, err)

				assert.DeepEqual(t, expectedUsers, users)
			},
		},
		{
			name: "user get users",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				_, user01Token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user01Token)

				_, _, err := gwClient.GetUsers(ctx, nil)
				expectedErr := remoteErrorUnauthorized
				assert.Error(t, err, expectedErr)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			tt.f(ctx, t, sc)
		})
	}
}

func TestGetUsers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir)
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	users := []*gwapitypes.UserResponse{}
	for i := 1; i < 10; i++ {
		user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: fmt.Sprintf("orguser%d", i)})
		testutil.NilError(t, err)

		users = append(users, user)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       gwapitypes.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "get users with limit = 0, no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "get users with limit = 0",
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get users with limit less than results length",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get users with limit greater than results length",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get users with limit = 0, sortDirection desc",
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get users with limit less than results length, sortDirection desc",
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get users with limit greater than results length, sortDirection desc",
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedUsers := append([]*gwapitypes.UserResponse{}, users...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedUsers)-1; i < j; i, j = i+1, j-1 {
					expectedUsers[i], expectedUsers[j] = expectedUsers[j], expectedUsers[i]
				}
			}

			respAllUsers := []*gwapitypes.UserResponse{}
			sortDirection := tt.sortDirection
			callsNumber := 0
			var cursor string

			for {
				respUsers, res, err := gwClient.GetUsers(ctx, &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				for _, respUser := range respUsers {
					respAllUsers = append(respAllUsers, &gwapitypes.UserResponse{ID: respUser.ID, UserName: respUser.UserName})
				}

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
			}

			assert.DeepEqual(t, expectedUsers, respAllUsers)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestCommitStatusDelivery(t *testing.T) {
	tests := []struct {
		name                     string
		config                   string
		expectedRunResult        rstypes.RunResult
		expectedRunPhase         rstypes.RunPhase
		expectedGiteaStatusState gitea.StatusState
		expectedGiteaDescription string
		expectedGiteaContext     string
	}{
		{
			name:                     "run result success",
			config:                   EnvRunConfig,
			expectedRunResult:        rstypes.RunResultSuccess,
			expectedRunPhase:         rstypes.RunPhaseFinished,
			expectedGiteaStatusState: gitea.StatusSuccess,
			expectedGiteaDescription: "The run finished successfully",
			expectedGiteaContext:     "agola/project01/run01",
		},
		{
			name:                     "run result failed",
			config:                   FailingRunConfig,
			expectedRunResult:        rstypes.RunResultFailed,
			expectedRunPhase:         rstypes.RunPhaseFinished,
			expectedGiteaStatusState: gitea.StatusFailure,
			expectedGiteaDescription: "The run failed",
			expectedGiteaContext:     "agola/project01/run01",
		},
		{
			name: "run setup config error",
			config: `
				{
				  runserror:
				}
				`,
			expectedRunResult:        rstypes.RunResultUnknown,
			expectedRunPhase:         rstypes.RunPhaseSetupError,
			expectedGiteaStatusState: gitea.StatusError,
			expectedGiteaDescription: "The run encountered an error",
			expectedGiteaContext:     "agola/project01/Setup Error",
		},
	}

	// it has been copied from the notification service
	webRunURL := func(webExposedURL, projectID string, runNumber uint64) (string, error) {
		u, err := url.Parse(webExposedURL + "/run")
		if err != nil {
			return "", errors.WithStack(err)
		}
		q := url.Values{}
		q.Set("projectref", projectID)
		q.Set("runnumber", strconv.FormatUint(runNumber, 10))

		u.RawQuery = q.Encode()

		return u.String(), nil
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			testutil.NilError(t, err)

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, "commit", false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				if runs[0].Phase != tt.expectedRunPhase {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			assert.Equal(t, runs[0].Phase, tt.expectedRunPhase)
			assert.Equal(t, runs[0].Result, tt.expectedRunResult)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				combinedStatus, _, err := giteaClient.GetCombinedStatus(agolaUser01, giteaRepo.Name, "master")
				if err != nil {
					return false, nil
				}

				if combinedStatus.State != tt.expectedGiteaStatusState {
					return false, nil
				}

				return true, nil
			})

			targetURL, err := webRunURL(sc.config.Notification.WebExposedURL, project.ID, runs[0].Number)
			testutil.NilError(t, err)

			combinedStatus, _, err := giteaClient.GetCombinedStatus(agolaUser01, giteaRepo.Name, "master")
			testutil.NilError(t, err)

			assert.Equal(t, combinedStatus.State, tt.expectedGiteaStatusState)
			assert.Equal(t, combinedStatus.Statuses[0].Description, tt.expectedGiteaDescription)
			assert.Equal(t, combinedStatus.Statuses[0].Context, tt.expectedGiteaContext)
			assert.Equal(t, combinedStatus.Statuses[0].TargetURL, targetURL)
		})
	}
}

func TestGetProjectRunWebhookDeliveries(t *testing.T) {
	t.Parallel()

	config := `
		{
			runs: [
				{
					name: 'run01',
					tasks: [
						{
							name: 'task01',
							runtime: {
								containers: [
									{
											image: 'alpine/git',
									},
								],
							},
							steps: [
								{ type: 'run', command: 'env' },
								{ type: 'run', command: 'echo %d' },
							],
						},
					],
				},
			],
		}
	`

	dir := t.TempDir()
	wrDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wr := setupWebhooksReceiver(ctx, t, wrDir)
	defer wr.stop()

	sc := setup(ctx, t, dir, withGitea(true), withWebhooks(fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks"), webhookSecret))
	defer sc.stop()

	giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
	gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
	gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
	testutil.NilError(t, err)

	gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	testutil.NilError(t, err)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

	runCount := 5

	for i := 0; i < runCount; i++ {
		push(t, fmt.Sprintf(config, i), giteaRepo.CloneURL, giteaToken, "commit", false)
	}

	_ = testutil.Wait(60*time.Second, func() (bool, error) {
		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		if err != nil {
			return false, nil
		}

		if len(runs) != runCount {
			return false, nil
		}
		for i := 0; i < runCount; i++ {
			if runs[i].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}
		}

		return true, nil
	})

	runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, runCount))
	for i := 0; i < runCount; i++ {
		assert.Equal(t, runs[i].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[i].Result, rstypes.RunResultSuccess)
	}

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		if err != nil {
			return false, nil
		}

		if len(runWebhookDeliveries) != 4*runCount {
			return false, nil
		}
		for _, r := range runWebhookDeliveries {
			if r.DeliveryStatus != gwapitypes.DeliveryStatusDelivered {
				return false, nil
			}
		}

		return true, nil
	})

	runWebhookDeliveries, resp, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runWebhookDeliveries, 4*runCount))
	assert.Assert(t, resp.Cursor == "")
	for _, r := range runWebhookDeliveries {
		assert.Assert(t, cmp.Equal(r.DeliveryStatus, gwapitypes.DeliveryStatusDelivered))
	}

	t.Run("request with cursor and deliveryStatusFilter", func(t *testing.T) {
		deliveryStatusFilter := []string{"delivered"}

		_, res, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 2, SortDirection: gwapitypes.SortDirectionAsc}, DeliveryStatusFilter: deliveryStatusFilter})
		testutil.NilError(t, err)

		_, _, err = gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Cursor: res.Cursor, Limit: 2, SortDirection: gwapitypes.SortDirectionAsc}, DeliveryStatusFilter: deliveryStatusFilter})
		assert.Error(t, err, remoteErrorBadRequest)
	})

	tests := []struct {
		name                 string
		client               *gwclient.Client
		projectRef           string
		limit                int
		sortDirection        gwapitypes.SortDirection
		deliveryStatusFilter []string
		expectedCallsNumber  int
		expectedErr          string
	}{
		{
			name:                "get project run webhook deliveries with limit = 0, no sortdirection",
			client:              gwUser01Client,
			projectRef:          project.ID,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project run webhook deliveries with limit = 0",
			client:              gwUser01Client,
			projectRef:          project.ID,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project run webhook deliveries with limit less than results length",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 10,
		},
		{
			name:                "get project run webhook deliveries with limit greater than results length",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project run webhook deliveries with limit = 0, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project run webhook deliveries with limit less than results length, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 10,
		},
		{
			name:                "get project run webhook deliveries with limit greater than results length, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                 "get project run webhook deliveries with limit less than results length, deliveryStatusFilter = delivered",
			client:               gwUser01Client,
			projectRef:           project.ID,
			limit:                2,
			sortDirection:        gwapitypes.SortDirectionAsc,
			deliveryStatusFilter: []string{"delivered"},
			expectedCallsNumber:  10,
		},
		{
			name:                 "get project run webhook deliveries with limit less than results length, deliveryStatusFilter = deliveryError",
			client:               gwUser01Client,
			projectRef:           project.ID,
			limit:                2,
			sortDirection:        gwapitypes.SortDirectionAsc,
			deliveryStatusFilter: []string{"deliveryError"},
			expectedCallsNumber:  1,
		},
		{
			name:          "get project run webhook deliveries with user unauthorized",
			client:        gwUser02Client,
			projectRef:    project.ID,
			sortDirection: gwapitypes.SortDirectionAsc,
			expectedErr:   remoteErrorForbidden,
		},
		{
			name:          "get project run webhook deliveries with not existing project",
			client:        gwUser01Client,
			projectRef:    "project02",
			sortDirection: gwapitypes.SortDirectionAsc,
			expectedErr:   remoteErrorNotExist,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// populate the expected commit status deliveries
			expectedProject01RunWebhookDeliveries := []*gwapitypes.RunWebhookDeliveryResponse{}
			for _, r := range runWebhookDeliveries {
				if len(tt.deliveryStatusFilter) > 0 && !util.StringInSlice(tt.deliveryStatusFilter, string(r.DeliveryStatus)) {
					continue
				}
				expectedProject01RunWebhookDeliveries = append(expectedProject01RunWebhookDeliveries, r)
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedProject01RunWebhookDeliveries)-1; i < j; i, j = i+1, j-1 {
					expectedProject01RunWebhookDeliveries[i], expectedProject01RunWebhookDeliveries[j] = expectedProject01RunWebhookDeliveries[j], expectedProject01RunWebhookDeliveries[i]
				}
			}

			respAllRunWebhookDeliveries := []*gwapitypes.RunWebhookDeliveryResponse{}
			sortDirection := tt.sortDirection
			deliveryStatusFilter := tt.deliveryStatusFilter
			callsNumber := 0
			var cursor string

			for {
				respRunWebhookDeliveries, res, err := tt.client.GetProjectRunWebhookDeliveries(ctx, tt.projectRef, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection}, DeliveryStatusFilter: deliveryStatusFilter})
				if tt.expectedErr == "" {
					testutil.NilError(t, err)
				} else {
					assert.Error(t, err, tt.expectedErr)
					return
				}

				callsNumber++

				respAllRunWebhookDeliveries = append(respAllRunWebhookDeliveries, respRunWebhookDeliveries...)

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
				deliveryStatusFilter = nil
			}

			assert.DeepEqual(t, expectedProject01RunWebhookDeliveries, respAllRunWebhookDeliveries)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestProjectRunWebhookRedelivery(t *testing.T) {
	t.Parallel()

	config := EnvRunConfig

	t.Run("redelivery project run webhook delivery with deliverystatus = deliveryError", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// set a fake webhookURL to make the delivery fail
		sc := setup(ctx, t, dir, withGitea(true), withWebhooks("fakeWebhookURL", webhookSecret))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
		gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

		_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, len(runs) != 0)

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 4 {
				return false, nil
			}
			for _, r := range runWebhookDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDeliveryError {
					return false, nil
				}
			}

			return true, nil
		})

		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 4))
		for _, r := range runWebhookDeliveries {
			assert.Equal(t, r.DeliveryStatus, gwapitypes.DeliveryStatusDeliveryError)
		}

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		testutil.NilError(t, err)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 5 {
				return false, nil
			}

			return true, nil
		})
		runWebhookDeliveries, _, err = gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 5))

		_, err = gwUser02Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		expectedErr := remoteErrorForbidden
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with deliverystatus = delivered", func(t *testing.T) {
		dir := t.TempDir()
		wrDir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		wr := setupWebhooksReceiver(ctx, t, wrDir)
		defer wr.stop()

		sc := setup(ctx, t, dir, withGitea(true), withWebhooks(fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks"), webhookSecret))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
		gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

		_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, len(runs) > 0)

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 4 {
				return false, nil
			}
			for _, r := range runWebhookDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDelivered {
					return false, nil
				}
			}

			return true, nil
		})

		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 4))
		for _, r := range runWebhookDeliveries {
			assert.Equal(t, r.DeliveryStatus, gwapitypes.DeliveryStatusDelivered)
		}

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		testutil.NilError(t, err)

		runWebhookDeliveries, _, err = gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 5))

		_, err = gwUser02Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		expectedErr := remoteErrorForbidden
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with not existing project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		_, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		_, err := gwUser01Client.ProjectRunWebhookRedelivery(ctx, "projecttestid", "runwebhookdeliverytestid")
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with not existing run webhook delivery", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		_, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project.ID, "runwebhookdeliverytestid")
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with projectRef that belong to another project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// set a fake webhookURL to make the delivery fail
		sc := setup(ctx, t, dir, withGitea(true), withWebhooks("fakeWebhookURL", webhookSecret))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project01 := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		project02, _, err := gwUser01Client.CreateProject(ctx, &gwapitypes.CreateProjectRequest{
			Name:             "project02",
			ParentRef:        path.Join("user", agolaUser01),
			RemoteSourceName: "gitea",
			RepoPath:         path.Join(giteaUser01, "repo01"),
			Visibility:       gwapitypes.VisibilityPublic,
		})
		testutil.NilError(t, err)

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project01.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project01.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, len(runs) > 0)

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project01.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 4 {
				return false, nil
			}
			for _, r := range runWebhookDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDeliveryError {
					return false, nil
				}
			}

			return true, nil
		})

		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project01.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 4))
		for _, r := range runWebhookDeliveries {
			assert.Equal(t, r.DeliveryStatus, gwapitypes.DeliveryStatusDeliveryError)
		}

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project02.ID, runWebhookDeliveries[0].ID)
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})
}

func TestGetProjectCommitStatusDeliveries(t *testing.T) {
	t.Parallel()

	config := `
		{
			runs: [
				{
					name: 'run01',
					tasks: [
						{
							name: 'task01',
							runtime: {
								containers: [
									{
											image: 'alpine/git',
									},
								],
							},
							steps: [
								{ type: 'run', command: 'env' },
								{ type: 'run', command: 'echo %d' },
							],
						},
					],
				},
			],
		}
	`

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
	gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
	gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
	testutil.NilError(t, err)

	gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	testutil.NilError(t, err)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

	runCount := 5

	for i := 0; i < runCount; i++ {
		push(t, fmt.Sprintf(config, i), giteaRepo.CloneURL, giteaToken, "commit", false)
	}

	_ = testutil.Wait(60*time.Second, func() (bool, error) {
		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, true)
		if err != nil {
			return false, nil
		}

		if len(runs) != runCount {
			return false, nil
		}
		for i := 0; i < runCount; i++ {
			if runs[i].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}
		}

		return true, nil
	})

	runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, true)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, runCount))
	for i := 0; i < runCount; i++ {
		assert.Equal(t, runs[i].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[i].Result, rstypes.RunResultSuccess)
	}

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		commitStatusDeliveries, _, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		if err != nil {
			return false, nil
		}

		if len(commitStatusDeliveries) != 2*runCount {
			return false, nil
		}
		for _, r := range commitStatusDeliveries {
			if r.DeliveryStatus != gwapitypes.DeliveryStatusDelivered {
				return false, nil
			}
		}

		return true, nil
	})

	commitStatusDeliveries, resp, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{SortDirection: gwapitypes.SortDirectionAsc}})
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(commitStatusDeliveries, 2*runCount))
	assert.Assert(t, resp.Cursor == "")
	for _, r := range commitStatusDeliveries {
		assert.Assert(t, cmp.Equal(r.DeliveryStatus, gwapitypes.DeliveryStatusDelivered))
	}

	t.Run("request with cursor and deliveryStatusFilter", func(t *testing.T) {
		deliveryStatusFilter := []string{"delivered"}

		_, res, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 2, SortDirection: gwapitypes.SortDirectionAsc}, DeliveryStatusFilter: deliveryStatusFilter})
		testutil.NilError(t, err)

		_, _, err = gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Cursor: res.Cursor, Limit: 2, SortDirection: gwapitypes.SortDirectionAsc}, DeliveryStatusFilter: deliveryStatusFilter})
		assert.Error(t, err, remoteErrorBadRequest)
	})

	tests := []struct {
		name                 string
		client               *gwclient.Client
		projectRef           string
		limit                int
		sortDirection        gwapitypes.SortDirection
		deliveryStatusFilter []string
		expectedCallsNumber  int
		expectedErr          string
	}{
		{
			name:                "get project commit status deliveries with limit = 0, no sortdirection",
			client:              gwUser01Client,
			projectRef:          project.ID,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project commit status deliveries with limit = 0",
			client:              gwUser01Client,
			projectRef:          project.ID,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project commit status deliveries with limit less than results length",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get project commit status deliveries with limit greater than results length",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project commit status deliveries with limit = 0, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "get project commit status deliveries with limit less than results length, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               2,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "get project commit status deliveries with limit greater than results length, sortDirection desc",
			client:              gwUser01Client,
			projectRef:          project.ID,
			limit:               MaxLimit,
			sortDirection:       gwapitypes.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                 "get project commit status deliveries with limit less than results length, deliveryStatusFilter = delivered",
			client:               gwUser01Client,
			projectRef:           project.ID,
			limit:                2,
			sortDirection:        gwapitypes.SortDirectionAsc,
			deliveryStatusFilter: []string{"delivered"},
			expectedCallsNumber:  5,
		},
		{
			name:                 "get project commit status deliveries with limit less than results length, deliveryStatusFilter = deliveryError",
			client:               gwUser01Client,
			projectRef:           project.ID,
			limit:                2,
			sortDirection:        gwapitypes.SortDirectionAsc,
			deliveryStatusFilter: []string{"deliveryError"},
			expectedCallsNumber:  1,
		},
		{
			name:          "get project commit status deliveries with user unauthorized",
			client:        gwUser02Client,
			projectRef:    project.ID,
			sortDirection: gwapitypes.SortDirectionAsc,
			expectedErr:   remoteErrorForbidden,
		},
		{
			name:          "get project commit status deliveries with not existing project",
			client:        gwUser01Client,
			projectRef:    "project02",
			sortDirection: gwapitypes.SortDirectionAsc,
			expectedErr:   remoteErrorNotExist,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// populate the expected commit status deliveries
			expectedProject01CommitStatusDeliveries := []*gwapitypes.CommitStatusDeliveryResponse{}
			for _, c := range commitStatusDeliveries {
				if len(tt.deliveryStatusFilter) > 0 && !util.StringInSlice(tt.deliveryStatusFilter, string(c.DeliveryStatus)) {
					continue
				}
				expectedProject01CommitStatusDeliveries = append(expectedProject01CommitStatusDeliveries, c)
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == gwapitypes.SortDirectionDesc {
				for i, j := 0, len(expectedProject01CommitStatusDeliveries)-1; i < j; i, j = i+1, j-1 {
					expectedProject01CommitStatusDeliveries[i], expectedProject01CommitStatusDeliveries[j] = expectedProject01CommitStatusDeliveries[j], expectedProject01CommitStatusDeliveries[i]
				}
			}

			respAllCommitStatusDeliveries := []*gwapitypes.CommitStatusDeliveryResponse{}
			sortDirection := tt.sortDirection
			deliveryStatusFilter := tt.deliveryStatusFilter
			callsNumber := 0
			var cursor string

			for {
				respCommitStatusDeliveries, res, err := tt.client.GetProjectCommitStatusDeliveries(ctx, tt.projectRef, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Cursor: cursor, Limit: tt.limit, SortDirection: sortDirection}, DeliveryStatusFilter: deliveryStatusFilter})
				if tt.expectedErr == "" {
					testutil.NilError(t, err)
				} else {
					assert.Error(t, err, tt.expectedErr)
					return
				}

				testutil.NilError(t, err)

				callsNumber++

				respAllCommitStatusDeliveries = append(respAllCommitStatusDeliveries, respCommitStatusDeliveries...)

				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
				sortDirection = ""
				deliveryStatusFilter = nil
			}

			assert.DeepEqual(t, expectedProject01CommitStatusDeliveries, respAllCommitStatusDeliveries)
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestProjectCommitStatusRedelivery(t *testing.T) {
	t.Parallel()

	config := EnvRunConfig

	t.Run("redelivery project commit status delivery with deliverystatus = deliveryError", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
		gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

		_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runs, 1))

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			commitStatusDeliveries, _, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(commitStatusDeliveries) != 2 {
				return false, nil
			}
			for _, r := range commitStatusDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDeliveryError {
					return false, nil
				}
			}

			return true, nil
		})

		// set a fake APIURL to make the delivery fail
		_, _, err = gwUserAdminClient.UpdateRemoteSource(ctx, "gitea", &gwapitypes.UpdateRemoteSourceRequest{APIURL: util.StringP("fakeGiteaAPIURL")})
		testutil.NilError(t, err)

		commitStatusDeliveries, _, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(commitStatusDeliveries, 2))
		for _, r := range commitStatusDeliveries {
			assert.Assert(t, cmp.Equal(r.DeliveryStatus, gwapitypes.DeliveryStatusDelivered))
		}

		_, err = gwUser01Client.ProjectCommitStatusRedelivery(ctx, project.ID, commitStatusDeliveries[0].ID)
		testutil.NilError(t, err)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			commitStatusDeliveries, _, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionDesc}})
			if err != nil {
				return false, nil
			}

			if len(commitStatusDeliveries) != 3 {
				return false, nil
			}
			if commitStatusDeliveries[0].DeliveryStatus != gwapitypes.DeliveryStatusDeliveryError {
				return false, nil
			}

			return true, nil
		})

		commitStatusDeliveries, _, err = gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 1, SortDirection: gwapitypes.SortDirectionDesc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(commitStatusDeliveries, 1))
		assert.Assert(t, cmp.Equal(commitStatusDeliveries[0].DeliveryStatus, gwapitypes.DeliveryStatusDeliveryError))

		_, err = gwUser01Client.ProjectCommitStatusRedelivery(ctx, project.ID, commitStatusDeliveries[0].ID)
		testutil.NilError(t, err)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			commitStatusDeliveries, _, err := gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(commitStatusDeliveries) != 3 {
				return false, nil
			}

			return true, nil
		})

		commitStatusDeliveries, _, err = gwUser01Client.GetProjectCommitStatusDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(commitStatusDeliveries, 4))

		_, err = gwUser02Client.ProjectCommitStatusRedelivery(ctx, project.ID, commitStatusDeliveries[0].ID)
		expectedErr := remoteErrorForbidden
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with deliverystatus = delivered", func(t *testing.T) {
		dir := t.TempDir()
		wrDir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		wr := setupWebhooksReceiver(ctx, t, wrDir)
		defer wr.stop()

		sc := setup(ctx, t, dir, withGitea(true), withWebhooks(fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks"), webhookSecret))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)
		gwUserAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

		_, _, err := gwUserAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		user02Token, _, err := gwUserAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user02Token.Token)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runs, 1))

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 4 {
				return false, nil
			}
			for _, r := range runWebhookDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDelivered {
					return false, nil
				}
			}

			return true, nil
		})

		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 4))
		for _, r := range runWebhookDeliveries {
			assert.Assert(t, cmp.Equal(r.DeliveryStatus, gwapitypes.DeliveryStatusDelivered))
		}

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		testutil.NilError(t, err)

		runWebhookDeliveries, _, err = gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 5))

		_, err = gwUser02Client.ProjectRunWebhookRedelivery(ctx, project.ID, runWebhookDeliveries[0].ID)
		expectedErr := remoteErrorForbidden
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with not existing project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		_, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		_, err := gwUser01Client.ProjectRunWebhookRedelivery(ctx, "projecttestid", "runwebhookdeliverytestid")
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with not existing run webhook delivery", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		_, project := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project.ID, "runwebhookdeliverytestid")
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})

	t.Run("redelivery project run webhook delivery with projectRef that belong to another project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// set a fake webhookURL to make the delivery fail
		sc := setup(ctx, t, dir, withGitea(true), withWebhooks("fakeWebhookURL", webhookSecret))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project01 := createProject(ctx, t, giteaClient, gwUser01Client, withVisibility(gwapitypes.VisibilityPrivate))

		project02, _, err := gwUser01Client.CreateProject(ctx, &gwapitypes.CreateProjectRequest{
			Name:             "project02",
			ParentRef:        path.Join("user", agolaUser01),
			RemoteSourceName: "gitea",
			RepoPath:         path.Join(giteaUser01, "repo01"),
			Visibility:       gwapitypes.VisibilityPublic,
		})
		testutil.NilError(t, err)

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project01.ID, nil, nil, 0, 0, false)
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project01.ID, nil, nil, 0, 0, false)
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runs, 1))

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_ = testutil.Wait(30*time.Second, func() (bool, error) {
			runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project01.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
			if err != nil {
				return false, nil
			}

			if len(runWebhookDeliveries) != 4 {
				return false, nil
			}
			for _, r := range runWebhookDeliveries {
				if r.DeliveryStatus != gwapitypes.DeliveryStatusDeliveryError {
					return false, nil
				}
			}

			return true, nil
		})

		runWebhookDeliveries, _, err := gwUser01Client.GetProjectRunWebhookDeliveries(ctx, project01.ID, &gwclient.DeliveriesOptions{ListOptions: &gwclient.ListOptions{Limit: 0, SortDirection: gwapitypes.SortDirectionAsc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runWebhookDeliveries, 4))
		for _, r := range runWebhookDeliveries {
			assert.Equal(t, r.DeliveryStatus, gwapitypes.DeliveryStatusDeliveryError)
		}

		_, err = gwUser01Client.ProjectRunWebhookRedelivery(ctx, project02.ID, runWebhookDeliveries[0].ID)
		expectedErr := remoteErrorNotExist
		assert.Error(t, err, expectedErr)
	})
}

func TestMaintenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, sc *setupContext)
	}{
		{
			name: "admin user enable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				testutil.NilError(t, err)

				testutil.NilError(t, err)

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				testutil.NilError(t, err)
			},
		},
		{
			name: "user enable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				testutil.NilError(t, err)

				token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "tokenuser01"})
				testutil.NilError(t, err)

				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

				expectedErr := remoteErrorUnauthorized
				_, err = gwClient.EnableMaintenance(ctx, configstoreService)
				assert.Error(t, err, expectedErr)

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name: "user disable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				testutil.NilError(t, err)

				token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "tokenuser01"})
				testutil.NilError(t, err)

				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

				expectedErr := remoteErrorUnauthorized
				_, err = gwClient.DisableMaintenance(ctx, configstoreService)
				assert.Error(t, err, expectedErr)

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name: "admin user enable maintenance already enabled",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				testutil.NilError(t, err)

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				testutil.NilError(t, err)

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				expectedErr := remoteErrorBadRequest
				_, err = gwClient.EnableMaintenance(ctx, configstoreService)
				assert.Error(t, err, expectedErr)

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name: "admin user disable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				testutil.NilError(t, err)

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				_, err = gwClient.DisableMaintenance(ctx, configstoreService)
				testutil.NilError(t, err)

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				testutil.NilError(t, err)

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, runserviceService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				testutil.NilError(t, err)
			},
		},
		{
			name: "admin user disable maintenance already disabled",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				expectedErr := remoteErrorBadRequest
				_, err := gwClient.DisableMaintenance(ctx, configstoreService)
				assert.Error(t, err, expectedErr)

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				assert.Error(t, err, expectedErr)
			},
		},
		{
			name: "wrong provided servicename",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				expectedErr := remoteErrorBadRequest
				_, err := gwClient.EnableMaintenance(ctx, "test")
				assert.Error(t, err, expectedErr)

				_, err = gwClient.DisableMaintenance(ctx, "test")
				assert.Error(t, err, expectedErr)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir)
			defer sc.stop()

			tt.f(ctx, t, sc)
		})
	}
}

func TestExportImport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	testutil.NilError(t, err)

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

	config := EnvRunConfig

	push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
		if err != nil {
			return false, nil
		}

		if len(runs) == 0 {
			return false, nil
		}
		run := runs[0]
		if run.Phase != rstypes.RunPhaseFinished {
			return false, nil
		}

		return true, nil
	})

	runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, 1))

	gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	users, _, err := gwClient.GetUsers(ctx, nil)
	testutil.NilError(t, err)

	projectgroup, _, err := gwClient.GetProjectGroup(ctx, "user/user01")
	testutil.NilError(t, err)

	remotesources, _, err := gwClient.GetRemoteSources(ctx, nil)
	testutil.NilError(t, err)

	user01Projects, _, err := gwClient.GetProjectGroupProjects(ctx, "user/user01")
	testutil.NilError(t, err)

	w, err := os.Create(filepath.Join(dir, "export-configstore"))
	testutil.NilError(t, err)

	resp, err := gwClient.Export(ctx, configstoreService)
	testutil.NilError(t, err)

	defer resp.Body.Close()

	_, err = io.Copy(w, resp.Body)
	testutil.NilError(t, err)

	w, err = os.Create(filepath.Join(dir, "export-runservice"))
	testutil.NilError(t, err)

	resp, err = gwClient.Export(ctx, runserviceService)
	testutil.NilError(t, err)

	defer resp.Body.Close()

	_, err = io.Copy(w, resp.Body)
	testutil.NilError(t, err)

	//add some data
	_, _, err = gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	_, _, err = gwClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
		Name:                "github",
		Type:                "gitea",
		APIURL:              giteaAPIURL,
		AuthType:            "password",
		SkipSSHHostKeyCheck: true,
	})
	testutil.NilError(t, err)

	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	_, err = gwClient.EnableMaintenance(ctx, configstoreService)
	testutil.NilError(t, err)

	_, err = gwClient.EnableMaintenance(ctx, runserviceService)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
		if err != nil {
			return false, nil
		}
		if !maintenanceStatus.CurrentStatus {
			return false, nil
		}

		maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
		if err != nil {
			return false, nil
		}
		if !maintenanceStatus.CurrentStatus {
			return false, nil
		}

		return true, nil
	})

	r, err := os.Open(filepath.Join(dir, "export-configstore"))
	testutil.NilError(t, err)

	_, err = gwClient.Import(ctx, configstoreService, r)
	testutil.NilError(t, err)

	_, err = gwClient.DisableMaintenance(ctx, configstoreService)
	testutil.NilError(t, err)

	_, err = gwClient.DisableMaintenance(ctx, runserviceService)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
		if err != nil {
			return false, nil
		}
		if maintenanceStatus.CurrentStatus {
			return false, nil
		}

		maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
		if err != nil {
			return false, nil
		}
		if maintenanceStatus.CurrentStatus {
			return false, nil
		}

		return true, nil
	})

	impUsers, _, err := gwClient.GetUsers(ctx, nil)
	testutil.NilError(t, err)

	assert.DeepEqual(t, users, impUsers)

	impProjectgroup, _, err := gwClient.GetProjectGroup(ctx, "user/user01")
	testutil.NilError(t, err)

	assert.DeepEqual(t, projectgroup, impProjectgroup)

	impRemotesources, _, err := gwClient.GetRemoteSources(ctx, nil)
	testutil.NilError(t, err)

	assert.DeepEqual(t, remotesources, impRemotesources)

	impUser01Projects, _, err := gwClient.GetProjectGroupProjects(ctx, "user/user01")
	testutil.NilError(t, err)

	assert.DeepEqual(t, user01Projects, impUser01Projects)

	impRuns, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
	testutil.NilError(t, err)

	assert.DeepEqual(t, runs, impRuns)

	orgs, _, err := gwClient.GetOrgs(ctx, nil)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(orgs, 0))
}
