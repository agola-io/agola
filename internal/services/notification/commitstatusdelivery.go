// Copyright 2023 Sorint.lab
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

package notification

import (
	"context"
	"time"

	"github.com/sorintlab/errors"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	cstypes "agola.io/agola/services/configstore/types"
	"agola.io/agola/services/notification/types"
)

const (
	maxCommitStatusDeliveriesQueryLimit = 40
	CommitStatusDeliveriesLockKey       = "commitstatusdeliveryevents"

	// commitstatusDeliveriesInterval is the time to wait between every commitStatusDeliveriesHandler call.
	commitstatusDeliveriesInterval = time.Second * 1
)

func (n *NotificationService) CommitStatusDeliveriesHandlerLoop(ctx context.Context) {
	for {
		if err := n.commitStatusDeliveriesHandler(ctx); err != nil {
			n.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(commitstatusDeliveriesInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) commitStatusDeliveriesHandler(ctx context.Context) error {
	l := n.lf.NewLock(CommitStatusDeliveriesLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	curCommitStatusDeliverySequence := uint64(0)

	for {
		var commitStatusDeliveries []*types.CommitStatusDelivery

		err := n.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			commitStatusDeliveries, err = n.d.GetProjectCommitStatusDeliveriesAfterSequenceByProjectID(tx, curCommitStatusDeliverySequence, "", []types.DeliveryStatus{types.DeliveryStatusNotDelivered}, maxCommitStatusDeliveriesQueryLimit, types.SortDirectionAsc)
			if err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		for _, c := range commitStatusDeliveries {
			if err := n.handleCommitStatusDelivery(ctx, c.ID); err != nil {
				n.log.Err(err).Msgf("failed to trigger commit status data delivery event")
			}

			curCommitStatusDeliverySequence = c.Sequence
		}

		if len(commitStatusDeliveries) < maxCommitStatusDeliveriesQueryLimit {
			return nil
		}
	}
}

func (n *NotificationService) handleCommitStatusDelivery(ctx context.Context, commitStatusDeliveryID string) error {
	var commitStatus *types.CommitStatus

	err := n.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		commitStatusDelivery, err := n.d.GetCommitStatusDeliveryByID(tx, commitStatusDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}

		if commitStatusDelivery.DeliveryStatus != types.DeliveryStatusNotDelivered {
			return nil
		}

		commitStatus, err = n.d.GetCommitStatusByID(tx, commitStatusDelivery.CommitStatusID)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}
	if commitStatus == nil {
		return nil
	}

	delivered, err := n.u.updateCommitStatus(ctx, commitStatus)
	// err != nil is considered a failed delivery
	if err != nil {
		n.log.Err(err).Send()
	}

	var deliveredAt *time.Time
	if delivered {
		deliveredAt = util.Ptr(time.Now())
	}

	err = n.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		commitStatusDelivery, err := n.d.GetCommitStatusDeliveryByID(tx, commitStatusDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}
		if commitStatusDelivery.DeliveryStatus != types.DeliveryStatusNotDelivered {
			return nil
		}

		if delivered {
			commitStatusDelivery.DeliveryStatus = types.DeliveryStatusDelivered
		} else {
			commitStatusDelivery.DeliveryStatus = types.DeliveryStatusDeliveryError
		}

		commitStatusDelivery.DeliveredAt = deliveredAt

		if err = n.d.UpdateCommitStatusDelivery(tx, commitStatusDelivery); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type GitSourceCommitStatusUpdater struct {
	configstoreClient *csclient.Client
	c                 *config.Notification
}

func (g *GitSourceCommitStatusUpdater) updateCommitStatus(ctx context.Context, commitStatus *types.CommitStatus) (bool, error) {
	var state gitsource.CommitStatus
	switch commitStatus.State {
	case types.CommitStateError:
		state = gitsource.CommitStatusError
	case types.CommitStateFailed:
		state = gitsource.CommitStatusFailed
	case types.CommitStatePending:
		state = gitsource.CommitStatusPending
	case types.CommitStateSuccess:
		state = gitsource.CommitStatusSuccess
	default:
		return false, errors.Errorf("commit status %s is not valid", commitStatus.State)
	}

	project, _, err := g.configstoreClient.GetProject(ctx, commitStatus.ProjectID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get project %s", commitStatus.ProjectID)
	}

	user, _, err := g.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get user by linked account %q", project.LinkedAccountID)
	}

	linkedAccounts, _, err := g.configstoreClient.GetUserLinkedAccounts(ctx, user.ID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get user %q linked accounts", user.Name)
	}

	var la *cstypes.LinkedAccount
	for _, v := range linkedAccounts {
		if v.ID == project.LinkedAccountID {
			la = v
			break
		}
	}
	if la == nil {
		return false, errors.Errorf("linked account %q for user %q doesn't exist", project.LinkedAccountID, user.Name)
	}
	rs, _, err := g.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
	}

	// TODO(sgotti) handle refreshing oauth2 tokens
	gitSource, err := common.GetGitSource(rs, la)
	if err != nil {
		return false, errors.Wrapf(err, "failed to create gitea client")
	}

	targetURL, err := webRunURL(g.c.WebExposedURL, project.ID, commitStatus.RunCounter)
	if err != nil {
		return false, errors.Wrapf(err, "failed to generate commit status target url")
	}

	delivered, err := gitSource.CreateCommitStatus(project.RepositoryPath, commitStatus.CommitSHA, state, targetURL, commitStatus.Description, commitStatus.Context)
	if err != nil {
		return false, errors.WithStack(err)
	}

	return delivered, nil
}
