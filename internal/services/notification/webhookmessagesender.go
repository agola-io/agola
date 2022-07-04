// Copyright 2022 Sorint.lab
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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"agola.io/agola/internal/errors"
	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/lock"
	"agola.io/agola/internal/services/common"
	cstypes "agola.io/agola/services/configstore/types"
)

const (
	RunWebhookMessagesLockKey = "webhookmessages"
)

func (n *NotificationService) webhooksSenderHandlerLoop(ctx context.Context) {
	for {
		if err := n.webhooksSenderHandler(ctx); err != nil {
			n.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) webhooksSenderHandler(ctx context.Context) error {
	l := n.lf.NewLock(RunWebhookMessagesLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	webhookMessages, _, err := n.configstoreClient.GetWebhookMessages(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, webhookMessage := range webhookMessages {
		if err = n.sendWebhookMessage(ctx, webhookMessage); err != nil {
			return errors.WithStack(err)
		} else {
			if _, err = n.configstoreClient.DeleteWebookMessage(ctx, webhookMessage.ID); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}

func (n *NotificationService) sendWebhookMessage(ctx context.Context, webhookMessage *cstypes.WebhookMessage) error {
	if webhookMessage.IsCustom {
		return n.sendCustomWebhookMessage(ctx, webhookMessage)
	} else {
		return n.sendGitsourceWebhookMessage(ctx, webhookMessage)
	}
}

func (n *NotificationService) sendGitsourceWebhookMessage(ctx context.Context, webhookMessage *cstypes.WebhookMessage) error {
	project, _, err := n.configstoreClient.GetProject(ctx, *webhookMessage.ProjectID)
	if err != nil {
		return errors.Wrapf(err, "failed to get project %s", *webhookMessage.ProjectID)
	}

	user, _, err := n.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return errors.Wrapf(err, "failed to get user by linked account %q", project.LinkedAccountID)
	}

	linkedAccounts, _, err := n.configstoreClient.GetUserLinkedAccounts(ctx, user.ID)
	if err != nil {
		return errors.Wrapf(err, "failed to get user %q linked accounts", user.Name)
	}

	var la *cstypes.LinkedAccount
	for _, v := range linkedAccounts {
		if v.ID == project.LinkedAccountID {
			la = v
			break
		}
	}
	if la == nil {
		return errors.Errorf("linked account %q for user %q doesn't exist", project.LinkedAccountID, user.Name)
	}

	rs, _, err := n.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
	}

	// TODO(sgotti) handle refreshing oauth2 tokens
	gitSource, err := common.GetGitSource(rs, la)
	if err != nil {
		return errors.Wrapf(err, "failed to create gitea client")
	}

	if err := gitSource.CreateCommitStatus(project.RepositoryPath, webhookMessage.CommitSha, gitsource.CommitStatus(webhookMessage.CommitStatus), webhookMessage.TargetURL, webhookMessage.Description, webhookMessage.StatusContext); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type WemhookMessage struct {
	TargetURL string `json:"target_url,omitempty"`

	CommitStatus string `json:"commit_status,omitempty"`

	Description string `json:"description,omitempty"`

	RepositoryPath string `json:"repository_path,omitempty"`

	CommitSha string `json:"commit_sha,omitempty"`

	Secret string `json:"secret,omitempty"`

	StatusContext string `json:"status_context,omitempty"`
}

func (n *NotificationService) sendCustomWebhookMessage(ctx context.Context, webhookMessage *cstypes.WebhookMessage) error {
	message := WemhookMessage{TargetURL: webhookMessage.TargetURL, CommitStatus: webhookMessage.CommitStatus, CommitSha: webhookMessage.CommitSha, Description: webhookMessage.Description, RepositoryPath: webhookMessage.RepositoryPath, StatusContext: webhookMessage.StatusContext, Secret: *webhookMessage.Secret}

	c := &http.Client{}

	body, err := json.Marshal(&message)
	if err != nil {
		return err
	}

	_, err = c.Post(*webhookMessage.DestinationURL, *webhookMessage.ContentType, bytes.NewReader(body))
	return errors.WithStack(err)
}
