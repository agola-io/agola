package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return an organization
// @Description Return an organization
// @Tags Organizations
// @Produce json
// @Param orgref path string true "Organization ref"
// @Success 200 {object} types.OrgResponse "ok"
// @Failure 404 "not found"
// @Router /orgs/{orgref} [get]
// @Security ApiKeyToken
func getOrganization() {}

// @Summary Return organizations list
// @Description Return organizations list
// @Tags Organizations
// @Produce json
// @Param limit query int false "limit response size"
// @Param asc query bool false "ascending ordering"
// @Param start query string false "start organization ref"
// @Success 200 {array} types.OrgResponse "ok"
// @Failure 400 "bad request"
// @Router /orgs [get]
// @Security ApiKeyToken
func getOrganizationList() {}

// @Summary Create an organization
// @Description Create an organization
// @Tags Organizations
// @Produce json
// @Param organization body types.CreateOrgRequest true "Organization request"
// @Success 201 {object} types.OrgResponse "created"
// @Failure 400 "bad request"
// @Router /orgs [post]
// @Security ApiKeyToken
func createOrganization() {}

// @Summary Delete an organization
// @Description Delete an organization
// @Tags Organizations
// @Produce json
// @Param orgref path string true "Organization ref"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /orgs/{orgref} [delete]
// @Security ApiKeyToken
func deleteOrganization() {}

// @Summary Return organization members
// @Description Return organization members
// @Tags Organizations
// @Produce json
// @Param orgref path string true "Organization ref"
// @Success 200 {object} types.OrgMembersResponse "ok"
// @Failure 404 "not found"
// @Router /orgs/{orgref}/members [get]
// @Security ApiKeyToken
func getOrganizationMembers() {}

// @Summary Add an organization member
// @Description Add an organization member
// @Tags Organizations
// @Produce json
// @Param orgref path string true "Organization ref"
// @Param userref path string true "User ref"
// @Param organization_member body types.AddOrgMemberRequest true "Organization member request"
// @Success 200 {object} types.AddOrgMemberResponse "ok"
// @Failure 400 "bad request"
// @Router /orgs/{orgref}/members/{userref} [put]
// @Security ApiKeyToken
func addOrganizationMember() {}

// @Summary Remove an organization member
// @Description Remove an organization member
// @Tags Organizations
// @Produce json
// @Param orgref path string true "Organization ref"
// @Param userref path string true "User ref"
// @Success 204 "no content"
// @Failure 400 "bad request"
// @Router /orgs/{orgref}/members/{userref} [delete]
// @Security ApiKeyToken
func remoteOrganizationMember() {}
