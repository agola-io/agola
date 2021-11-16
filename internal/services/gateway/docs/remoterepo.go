package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return user remote repo list
// @Description Return user remote repo list
// @Tags RemoteRepos
// @Produce json
// @Param remotesourceref path string true "Remotesource ref"
// @Success 200 {array} types.RemoteRepoResponse "ok"
// @Failure 400 "bad request"
// @Router /user/remoterepos/{remotesourceref} [get]
// @Security ApiKeyToken
func getUserRemoteRepos() {}
