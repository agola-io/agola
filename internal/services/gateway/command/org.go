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
	"context"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

type CreateOrgRequest struct {
	Name string
}

func (c *CommandHandler) CreateOrg(ctx context.Context, req *CreateOrgRequest) (*types.Organization, error) {
	if req.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("organization name required"))
	}
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid organization name %q", req.Name))
	}

	org := &types.Organization{
		Name: req.Name,
	}

	c.log.Infof("creating organization")
	org, _, err := c.configstoreClient.CreateOrg(ctx, org)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create organization")
	}
	c.log.Infof("organization %s created, ID: %s", org.Name, org.ID)

	return org, nil
}
