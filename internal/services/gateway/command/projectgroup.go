// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

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
		return nil, util.NewErrBadRequest(errors.Errorf("invalid projectGroup name %q", req.Name))
	}

	user, resp, err := c.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", req.CurrentUserID))
	}

	parentID := req.ParentID
	if parentID == "" {
		// create projectGroup in current user namespace
		parentID = path.Join("user", user.Name)
	}

	p := &types.ProjectGroup{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentID,
		},
	}

	c.log.Infof("creating projectGroup")
	p, resp, err = c.configstoreClient.CreateProjectGroup(ctx, p)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create projectGroup"))
	}
	c.log.Infof("projectGroup %s created, ID: %s", p.Name, p.ID)

	return p, nil
}
