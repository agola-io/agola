package docs

import (
	_ "agola.io/agola/services/gateway/api/types"
)

// @Summary Return the current user
// @Description Return the current user
// @Tags Users
// @Produce json
// @Success 200 {object} types.UserResponse "ok"
// @Failure 400 "bad request"
// @Router /user [get]
// @Security ApiKeyToken
func getCurrentUser() {}

// @Summary Return a user
// @Description Return a user
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Success 200 {object} types.UserResponse "ok"
// @Failure 404 "not found"
// @Router /users/{userref} [get]
// @Security ApiKeyToken
func getUser() {}

// @Summary Return users list
// @Description Return users list
// @Tags Users
// @Produce json
// @Param limit query int false "limit response size"
// @Param asc query bool false "ascending ordering"
// @Param start query string false "start user name"
// @Success 200 {array} types.UserResponse "ok"
// @Router /users [get]
// @Security ApiKeyToken
func getUserList() {}

// @Summary Create a user
// @Description Create a user
// @Tags Users
// @Produce json
// @Param secret body types.CreateUserRequest true "User request"
// @Success 201 {object} types.SecretResponse "created"
// @Failure 400 "bad request"
// @Router /users [post]
// @Security ApiKeyToken
func createUser() {}

// @Summary Delete a user
// @Description Delete a user
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /users/{userref} [delete]
// @Security ApiKeyToken
func deleteUser() {}

// @Summary Create a directrun
// @Description Create a directrun
// @Tags Users
// @Produce json
// @Param secret body types.UserCreateRunRequest true "Directrun request"
// @Success 201 "created"
// @Failure 400 "bad request"
// @Router /user/createrun [post]
// @Security ApiKeyToken
func createUserRun() {}

// @Summary Create a user linked account
// @Description Create a user linked account
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Param linkedAccount body types.CreateUserLARequest true "Linked account request"
// @Success 201 {object} types.CreateUserLAResponse "created"
// @Failure 400 "bad request"
// @Router /users/{userref}/linkedaccounts [post]
// @Security ApiKeyToken
func createUserLinkedAccount() {}

// @Summary Delete user linked account
// @Description Delete user linked account
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Param laid path string true "Linked account id"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /users/{userref}/linkedaccounts/{laid} [delete]
// @Security ApiKeyToken
func deleteUserLinkedAccount() {}

// @Summary Create a user token
// @Description Create a user token
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Param userToken body types.CreateUserTokenRequest true "User token request"
// @Success 201 {object} types.CreateUserTokenResponse "created"
// @Failure 400 "bad response"
// @Router /users/{userref}/tokens [post]
// @Security ApiKeyToken
func createUserToken() {}

// @Summary Delete a user token
// @Description Delete a user token
// @Tags Users
// @Produce json
// @Param userref path string true "User ref"
// @Param tokenname path string true "Token name"
// @Success 204 "no content"
// @Failure 404 "not found"
// @Router /users/{userref}/tokens/{tokenname} [delete]
// @Security ApiKeyToken
func deleteUserToken() {}

// @Summary Login
// @Description Login
// @Tags Users
// @Produce json
// @Param login body types.LoginUserRequest true "Login request"
// @Success 201 {object} types.LoginUserResponse"created"
// @Failure 400 "bad request"
// @Router /auth/login [post]
// @Security ApiKeyToken
func login() {}

// @Summary Authorize
// @Description Authorize
// @Tags Users
// @Produce json
// @Param authorize body types.LoginUserRequest true "Authorize request"
// @Success 201 {object} types.AuthorizeResponse"created"
// @Failure 400 "bad request"
// @Router /auth/authorize [post]
// @Security ApiKeyToken
func authorize() {}

// @Summary Register
// @Description Register
// @Tags Users
// @Produce json
// @Param register body types.RegisterUserRequest true "Register request"
// @Success 201 {object} types.RegisterUserResponse"created"
// @Failure 400 "bad request"
// @Router /auth/register [post]
// @Security ApiKeyToken
func register() {}
