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
	"path"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

type CreateProjectGroupRequest struct {
	Name          string
	ParentID      string
	CurrentUserID string
}

func (c *CommandHandler) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*types.ProjectGroup, error) {
	if !util.ValidateName(req.Name) {
		return nil, errors.Errorf("invalid projectGroup name %q", req.Name)
	}

	user, _, err := c.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %q", req.CurrentUserID)
	}

	parentID := req.ParentID
	if parentID == "" {
		// create projectGroup in current user namespace
		parentID = path.Join("user", user.UserName)
	}

	p := &types.ProjectGroup{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentID,
		},
	}

	c.log.Infof("creating projectGroup")
	p, _, err = c.configstoreClient.CreateProjectGroup(ctx, p)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create projectGroup")
	}
	c.log.Infof("projectGroup %s created, ID: %s", p.Name, p.ID)

	return p, nil
}
