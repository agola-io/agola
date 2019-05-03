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
	"encoding/json"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func (s *CommandHandler) CreateOrg(ctx context.Context, org *types.Organization) (*types.Organization, error) {
	if org.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("organization name required"))
	}
	if !util.ValidateName(org.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid organization name %q", org.Name))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the org name
	cgNames := []string{util.EncodeSha256Hex("orgname-" + org.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate org name
		u, err := s.readDB.GetOrgByName(tx, org.Name)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("org %q already exists", u.Name))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	org.ID = uuid.NewV4().String()
	orgj, err := json.Marshal(org)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal org")
	}

	pg := &types.ProjectGroup{
		ID: uuid.NewV4().String(),
		Parent: types.Parent{
			Type: types.ConfigTypeOrg,
			ID:   org.ID,
		},
	}
	pgj, err := json.Marshal(pg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project group")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeOrg),
			ID:         org.ID,
			Data:       orgj,
		},
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         pg.ID,
			Data:       pgj,
		},
	}

	_, err = s.dm.WriteWal(ctx, actions, cgt)
	return org, err
}

func (s *CommandHandler) DeleteOrg(ctx context.Context, orgRef string) error {
	var org *types.Organization
	var projects []*types.Project

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check org existance
		org, err = s.readDB.GetOrgByName(tx, orgRef)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrBadRequest(errors.Errorf("org %q doesn't exist", orgRef))
		}

		// changegroup is the org id
		cgNames := []string{util.EncodeSha256Hex("orgid-" + org.ID)}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// TODO(sgotti) delete all project groups, projects etc...
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeOrg),
			ID:         org.ID,
		},
	}
	// delete all org projects
	for _, project := range projects {
		actions = append(actions, &datamanager.Action{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		})
	}

	_, err = s.dm.WriteWal(ctx, actions, cgt)
	return err
}
