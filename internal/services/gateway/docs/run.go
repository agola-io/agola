package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return a run
// @Description Return a run
// @Tags Runs
// @Produce json
// @Param runid path string true "Run id"
// @Success 200 {object} types.RunResponse "ok"
// @Failure 404 "not found"
// @Router /runs/{runid} [get]
// @Security ApiKeyToken
func getRun() {}

// @Summary Execute a run action
// @Description Execute a run action
// @Tags Runs
// @Produce json
// @Param runid path string true "Run id"
// @Param action body types.RunActionsRequest true "Run action request"
// @Success 200 {object} types.RunResponse "ok"
// @Failure 404 "not found"
// @Router /runs/{runid}/actions [put]
// @Security ApiKeyToken
func executeRunAction() {}

// @Summary Return a task
// @Description Return a task
// @Tags Runs
// @Produce json
// @Param runid path string true "Run id"
// @Param taskid path string true "Task id"
// @Success 200 {object} types.RunTaskResponse "ok"
// @Failure 404 "not found"
// @Router /runs/{runid}/tasks/{taskid} [get]
// @Security ApiKeyToken
func getTask() {}

// @Summary Execute a task action
// @Description Execute a task action
// @Tags Runs
// @Produce json
// @Param runid path string true "Run id"
// @Param taskid path string true "Task id"
// @Param action body types.RunTaskActionsRequest true "Task action request"
// @Success 200 {object} types.RunResponse "ok"
// @Failure 404 "not found"
// @Router /runs/{runid}/tasks/{taskid}/actions [put]
// @Security ApiKeyToken
func executeTaskAction() {}

// @Summary Return runs list
// @Description Return runs list
// @Tags Runs
// @Produce json
// @Param limit query int false "limit response size"
// @Param asc query bool false "ascending ordering"
// @Param start query string false "start run id"
// @Param group query string true "group"
// @Param phase query string false "phase"
// @Param result query string false "result"
// @Param changegroup query string false "changegroup"
// @Param lastrun query bool false "last run"
// @Success 200 {array} types.RunsResponse "ok"
// @Failure 400 "bad request"
// @Router /runs [get]
// @Security ApiKeyToken
func getRunList() {}
