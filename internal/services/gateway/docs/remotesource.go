package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return a remotesource
// @Description Return a remotesource
// @Tags Remotesources
// @Produce json
// @Param remotesourceref path string true "Remotesource ref"
// @Success 200 {object} types.RemoteSourceResponse "ok"
// @Failure 404 "not found"
// @Router /remotesources/{remotesourceref} [get]
// @Security ApiKeyToken
//nolint
func getRemotesource() {}

// @Summary Create a remotesource
// @Description Create a remotesource
// @Tags Remotesources
// @Produce json
// @Param remotesource body types.CreateRemoteSourceRequest true "Remotesource request"
// @Success 201 {object} types.RemoteSourceResponse "created"
// @Failure 400 "bad request"
// @Router /remotesources [post]
// @Security ApiKeyToken
//nolint
func createRemotesource() {}

// @Summary Update a remotesource
// @Description Update a remotesource
// @Tags Remotesources
// @Produce json
// @Param remotesourceref path string true "Remotesource ref"
// @Param remotesource body types.UpdateRemoteSourceRequest true "Remotesource request"
// @Success 201 {object} types.RemoteSourceResponse "created"
// @Failure 400 "bad request"
// @Router /remotesources/{remotesourceref} [put]
// @Security ApiKeyToken
//nolint
func updateRemotesource() {}

// @Summary Return remotesources list
// @Description Return remotesources list
// @Tags Remotesources
// @Produce json
// @Param limit query int false "limit response size"
// @Param asc query bool false "ascending ordering"
// @Param start query string false "start remotesource ref"
// @Success 200 {array} types.RemoteSourceResponse "ok"
// @Failure 400 "bad request"
// @Router /remotesources [get]
// @Security ApiKeyToken
//nolint
func getRemotesourceList() {}

// @Summary Delete a remotesource
// @Description Delete a remotesource
// @Tags Remotesources
// @Produce json
// @Param remotesourceref path string true "Remotesource ref"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /remotesources/{remotesourceref} [delete]
// @Security ApiKeyToken
//nolint
func deleteRemotesource() {}
