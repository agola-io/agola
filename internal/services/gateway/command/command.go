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

package command

import (
	"net/http"

	"github.com/pkg/errors"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/util"

	"go.uber.org/zap"
)

type CommandHandler struct {
	log               *zap.SugaredLogger
	sd                *common.TokenSigningData
	configstoreClient *csapi.Client
	agolaID           string
	apiExposedURL     string
	webExposedURL     string
}

func NewCommandHandler(logger *zap.Logger, sd *common.TokenSigningData, configstoreClient *csapi.Client, agolaID, apiExposedURL, webExposedURL string) *CommandHandler {
	return &CommandHandler{
		log:               logger.Sugar(),
		sd:                sd,
		configstoreClient: configstoreClient,
		agolaID:           agolaID,
		apiExposedURL:     apiExposedURL,
		webExposedURL:     webExposedURL,
	}
}

func ErrFromRemote(resp *http.Response, err error) error {
	if err == nil {
		return nil
	}

	if resp != nil {
		switch resp.StatusCode {
		// remove wrapping from errors sent to client
		case http.StatusBadRequest:
			return util.NewErrBadRequest(errors.Cause(err))
		case http.StatusNotFound:
			return util.NewErrNotFound(errors.Cause(err))
		}
	}

	return err
}
