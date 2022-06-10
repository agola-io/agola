package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Create a project
// @Description Create a project
// @Tags Projects
// @Produce  json
// @Param project body types.CreateProjectRequest true "Project request"
// @Success 201 {object} types.ProjectResponse "created"
// @Failure 400 "bad request"
// @Router /projects [post]
// @Security ApiKeyToken
//nolint
func createProject() {}

// @Summary Update a project
// @Description Update a project
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Param project body types.UpdateProjectRequest true "Project request"
// @Success 201 {object} types.ProjectResponse "created"
// @Failure 400 "bad request"
// @Router /projects/{projectref} [put]
// @Security ApiKeyToken
//nolint
func updateProject() {}

// @Summary Reconfig a project
// @Description Reconfig a project
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Success 200 "ok"
// @Failure 404 "not found"
// @Router /projects/{projectref}/reconfig [put]
// @Security ApiKeyToken
//nolint
func reconfigProject() {}

// @Summary Update a project repository linked account
// @Description Update a project repository linked account
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Success 200 {object} types.ProjectResponse "ok"
// @Failure 404 "not found"
// @Router /projects/{projectref}/updaterepolinkedaccount [put]
// @Security ApiKeyToken
//nolint
func updateProjectRepoLinkedAccount() {}

// @Summary Delete a project
// @Description Delete a project
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projects/{projectref} [delete]
// @Security ApiKeyToken
//nolint
func deleteProject() {}

// @Summary Return a project
// @Description Return a project
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Success 200 {object} types.ProjectResponse "ok"
// @Failure 404 "not found"
// @Router /projects/{projectref} [get]
// @Security ApiKeyToken
//nolint
func getProject() {}

// @Summary Create a run
// @Description Create a run
// @Tags Projects
// @Produce  json
// @Param projectref path string true "Project ref"
// @Param run body types.ProjectCreateRunRequest true "Project run request"
// @Success 201 {object} types.ProjectGroupResponse "Created"
// @Failure 400 "bad request"
// @Router /projects/{projectref}/createrun [post]
// @Security ApiKeyToken
//nolint
func createRun() {}
