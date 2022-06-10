package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return a list of project secrets
// @Description Return a list of project secrets
// @Tags Secrets
// @Produce json
// @Param tree query bool false "secret tree"
// @Param removeoverridden query bool false "filter overridden"
// @Param projectref path string true "Project ref"
// @Success 200 {array} types.SecretResponse "ok"
// @Failure 404 "not found"
// @Router /projects/{projectref}/secrets [get]
// @Security ApiKeyToken
//nolint
func getProjectSecretList() {}

// @Summary Return a list of projectgroup secrets
// @Description Return a list of projectgroup secrets
// @Tags Secrets
// @Produce json
// @Param tree query bool false "secret tree"
// @Param removeoverridden query bool false "filter overridden"
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 200 {array} types.SecretResponse "ok"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/secrets [get]
// @Security ApiKeyToken
//nolint
func getProjectgroupSecretList() {}

// @Summary Create a projectgroup secret
// @Description Create a projectgroup secret
// @Tags Secrets
// @Produce json
// @Param secret body types.CreateSecretRequest true "Secret request"
// @Param projectgroupref path string true "Projectgroup ref"
// @Success 201 {object} types.SecretResponse "created"
// @Failure 400 "bad request"
// @Router /projectgroups/{projectgroupref}/secrets [post]
// @Security ApiKeyToken
//nolint
func createProjectgroupSecret() {}

// @Summary Create a project secret
// @Description Create a project secret
// @Tags Secrets
// @Produce json
// @Param secret body types.CreateSecretRequest true "Projectgroup request"
// @Param projectref path string true "Project ref"
// @Success 201 {object} types.SecretResponse "created"
// @Failure 400 "bad request"
// @Router /projects/{projectref}/secrets [post]
// @Security ApiKeyToken
//nolint
func createProjectSecret() {}

// @Summary Update a projectgroup secret
// @Description Update a projectgroup secret
// @Tags Secrets
// @Produce json
// @Param secret body types.UpdateSecretRequest true "Secret request"
// @Param projectgroupref path string true "Projectgroup ref"
// @Param secretname path string true "Secret name"
// @Success 200 {object} types.SecretResponse "ok"
// @Failure 400 "bad request"
// @Router /projectgroups/{projectgroupref}/secrets/{secretname} [put]
// @Security ApiKeyToken
//nolint
func updateProjectgroupSecret() {}

// @Summary Update a projectgroup secret
// @Description Update a projectgroup secret
// @Tags Secrets
// @Produce json
// @Param secret body types.UpdateSecretRequest true "Secret request"
// @Param projectref path string true "Project ref"
// @Param secretname path string true "Secret name"
// @Success 200 {object} types.SecretResponse "ok"
// @Failure 400 "bad request"
// @Router /projects/{projectref}/secrets/{secretname} [put]
// @Security ApiKeyToken
//nolint
func updateProjectSecret() {}

// @Summary Delete a projectgroup secret
// @Description Delete a projectgroup secret
// @Tags Secrets
// @Produce json
// @Param projectgroupref path string true "Projectgroup ref"
// @Param secretname path string true "Secret name"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projectgroups/{projectgroupref}/secrets/{secretname} [delete]
// @Security ApiKeyToken
//nolint
func deleteProjectgroupSecret() {}

// @Summary Delete a project secret
// @Description Delete a project secret
// @Tags Secrets
// @Produce json
// @Param projectref path string true "Project ref"
// @Param secretname path string true "Secret name"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /projects/{projectref}/secrets/{secretname} [delete]
// @Security ApiKeyToken
//nolint
func deleteProjectSecret() {}
