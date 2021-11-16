package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return a list of projectgroup variables
// @Description Return a list of projectgroup variables
// @Tags Variables
// @Produce json
// @Param tree query bool false "secret tree"
// @Param removeoverridden query bool false "filter overridden"
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 200 {array} types.VariableResponse "ok"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/variables [get]
// @Security ApiKeyToken
func getProjectgroupVariableList() {}

// @Summary Return a list of project variables
// @Description Return a list of project variables
// @Tags Variables
// @Produce json
// @Param tree query bool false "secret tree"
// @Param removeoverridden query bool false "filter overridden"
// @Param projectref path string true "Project ref"
// @Success 200 {array} types.VariableResponse "ok"
// @Failure 404 "not found"
// @Router /projects/{projectref}/variables [get]
// @Security ApiKeyToken
func getProjectVariableList() {}

// @Summary Create a projectgroup variable
// @Description Create a projectgroup variable
// @Tags Variables
// @Produce json
// @Param variable body types.CreateVariableRequest true "Variable request"
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 201 {object} types.VariableResponse "created"
// @Failure 400 "bad request"
// @Router /projectgroups/{projectgroupref}/variables [post]
// @Security ApiKeyToken
func createProjectgroupVariable() {}

// @Summary Create a project variable
// @Description Create a project variable
// @Tags Variables
// @Produce json
// @Param variable body types.CreateVariableRequest true "Variable request"
// @Param projectref path string true "Project ref"
// @Success 201 {object} types.VariableResponse "created"
// @Failure 400 "bad request"
// @Router /projects/{projectref}/variables [post]
// @Security ApiKeyToken
func createProjectVariable() {}

// @Summary Update a projectgroup variable
// @Description Update a projectgroup variable
// @Tags Variables
// @Produce json
// @Param variable body types.UpdateVariableRequest true "Variable request"
// @Param projectgroupref path string true "Projectgroup ref"
// @Param variablename path string true "Variable name"
// @Success 200 {object} types.VariableResponse "ok"
// @Failure 400 "bad request"
// @Router /projectgroups/{projectgroupref}/variables/{variablename} [put]
// @Security ApiKeyToken
func updateProjectgroupVariable() {}

// @Summary Update a project variable
// @Description Update a project variable
// @Tags Variables
// @Produce json
// @Param variable body types.UpdateVariableRequest true "Variable request"
// @Param projectref path string true "Project ref"
// @Param variablename path string true "Variable name"
// @Success 200 {object} types.VariableResponse "ok"
// @Failure 400 "bad request"
// @Router /projects/{projectref}/variables/{variablename} [put]
// @Security ApiKeyToken
func updateProjectVariable() {}

// @Summary Delete a projectgroup variable
// @Description Delete a projectgroup variable
// @Tags Variables
// @Produce json
// @Param projectgroupref path string true "Projectgroup ref"
// @Param variablename path string true "Variable name"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/variables/{variablename} [delete]
// @Security ApiKeyToken
func deleteProjectgroupVariable() {}

// @Summary Delete a project variable
// @Description Delete a project variable
// @Tags Variables
// @Produce json
// @Param projectref path string true "Project ref"
// @Param variablename path string true "Variable name"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projects/{projectref}/variables/{variablename} [delete]
// @Security ApiKeyToken
func deleteProjectVariable() {}
