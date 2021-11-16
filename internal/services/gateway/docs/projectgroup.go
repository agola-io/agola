package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Create a projectgroup
// @Description Create a projectggroup
// @Tags Projectgroups
// @Produce  json
// @Param projectgroup body types.CreateProjectGroupRequest true "Projectgroup request"
// @Success 201 {object} types.ProjectGroupResponse "created"
// @Failure 400 "bad request"
// @Router /projectgroups [post]
// @Security ApiKeyToken
func createProjectgroup() {}

// @Summary Update a projectgroup
// @Description Update a projectggroup
// @Tags Projectgroups
// @Produce  json
// @Param projectgroupref path string true "Projectgroup ref"
// @Param projectgroup body types.UpdateProjectGroupRequest true "Projectgroup request"
// @Success 201 {object} types.ProjectGroupResponse "created"
// @Failure 400 "bad request"
// @Router /projectgroups/{projectgroupref} [put]
// @Security ApiKeyToken
func updateProjectgroup() {}

// @Summary Delete a projectgroup
// @Description Delete a projectggroup
// @Tags Projectgroups
// @Produce  json
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref} [delete]
// @Security ApiKeyToken
func deleteProjectgroup() {}

// @Summary Return a projectgroup
// @Description Return a projectggroup
// @Tags Projectgroups
// @Produce  json
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 200 {object} types.ProjectGroupResponse "ok"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref} [get]
// @Security ApiKeyToken
func getProjectgroup() {}

// @Summary Return projectgroup projects
// @Description Return projectgroup projects
// @Tags Projectgroups
// @Produce  json
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 200 {array} types.ProjectResponse "ok"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/projects [get]
// @Security ApiKeyToken
func getProjectgroupProjects() {}

// @Summary Return projectgroup subgroups
// @Description Return a projectgroup subgroups
// @Tags Projectgroups
// @Produce  json
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 200 {array} types.ProjectGroupResponse "ok"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/subgroups [get]
// @Security ApiKeyToken
func getProjectgroupSubgroups() {}
