// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/gitsources/gitea"
	"github.com/sorintlab/agola/internal/gitsources/github"
	"github.com/sorintlab/agola/internal/gitsources/gitlab"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/pkg/errors"
)

func newGitea(rs *types.RemoteSource, accessToken string) (*gitea.Client, error) {
	return gitea.New(gitea.Opts{
		APIURL:         rs.APIURL,
		SkipVerify:     rs.SkipVerify,
		Token:          accessToken,
		Oauth2ClientID: rs.Oauth2ClientID,
		Oauth2Secret:   rs.Oauth2ClientSecret,
	})
}

func newGitlab(rs *types.RemoteSource, accessToken string) (*gitlab.Client, error) {
	return gitlab.New(gitlab.Opts{
		APIURL:         rs.APIURL,
		SkipVerify:     rs.SkipVerify,
		Token:          accessToken,
		Oauth2ClientID: rs.Oauth2ClientID,
		Oauth2Secret:   rs.Oauth2ClientSecret,
	})
}

func newGithub(rs *types.RemoteSource, accessToken string) (*github.Client, error) {
	return github.New(github.Opts{
		APIURL:         rs.APIURL,
		SkipVerify:     rs.SkipVerify,
		Token:          accessToken,
		Oauth2ClientID: rs.Oauth2ClientID,
		Oauth2Secret:   rs.Oauth2ClientSecret,
	})
}

func GetAccessToken(rs *types.RemoteSource, userAccessToken, oauth2AccessToken string) (string, error) {
	switch rs.AuthType {
	case types.RemoteSourceAuthTypePassword:
		return userAccessToken, nil
	case types.RemoteSourceAuthTypeOauth2:
		return oauth2AccessToken, nil
	default:
		return "", errors.Errorf("invalid remote source auth type %q", rs.AuthType)
	}
}

func GetGitSource(rs *types.RemoteSource, la *types.LinkedAccount) (gitsource.GitSource, error) {
	var accessToken string
	if la != nil {
		var err error
		accessToken, err = GetAccessToken(rs, la.UserAccessToken, la.Oauth2AccessToken)
		if err != nil {
			return nil, err
		}
	}

	var gitSource gitsource.GitSource
	var err error
	switch rs.Type {
	case types.RemoteSourceTypeGitea:
		gitSource, err = newGitea(rs, accessToken)
	case types.RemoteSourceTypeGitlab:
		gitSource, err = newGitlab(rs, accessToken)
	case types.RemoteSourceTypeGithub:
		gitSource, err = newGithub(rs, accessToken)
	default:
		return nil, errors.Errorf("remote source %s isn't a valid git source", rs.Name)
	}

	return gitSource, err
}

func GetUserSource(rs *types.RemoteSource, accessToken string) (gitsource.UserSource, error) {
	var userSource gitsource.UserSource
	var err error
	switch rs.AuthType {
	case types.RemoteSourceAuthTypeOauth2:
		userSource, err = GetOauth2Source(rs, accessToken)
	case types.RemoteSourceAuthTypePassword:
		userSource, err = GetPasswordSource(rs, accessToken)
	default:
		return nil, errors.Errorf("unknown remote source auth type")
	}

	return userSource, err
}

func GetOauth2Source(rs *types.RemoteSource, accessToken string) (gitsource.Oauth2Source, error) {
	var oauth2Source gitsource.Oauth2Source
	var err error
	switch rs.Type {
	case types.RemoteSourceTypeGitea:
		oauth2Source, err = newGitea(rs, accessToken)
	case types.RemoteSourceTypeGitlab:
		oauth2Source, err = newGitlab(rs, accessToken)
	case types.RemoteSourceTypeGithub:
		oauth2Source, err = newGithub(rs, accessToken)
	default:
		return nil, errors.Errorf("remote source %s isn't a valid oauth2 source", rs.Name)
	}

	return oauth2Source, err
}

func GetPasswordSource(rs *types.RemoteSource, accessToken string) (gitsource.PasswordSource, error) {
	var passwordSource gitsource.PasswordSource
	var err error
	switch rs.Type {
	case types.RemoteSourceTypeGitea:
		passwordSource, err = newGitea(rs, accessToken)
	default:
		return nil, errors.Errorf("remote source %s isn't a valid oauth2 source", rs.Name)
	}

	return passwordSource, err
}
