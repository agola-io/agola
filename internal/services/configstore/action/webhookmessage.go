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

package action

import (
	"context"
	"net/url"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetWebhookMessage(ctx context.Context, webhookMessageID string) (*types.WebhookMessage, error) {
	var webhookMessage *types.WebhookMessage
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		webhookMessage, err = h.d.GetWebhookMessage(tx, webhookMessageID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return webhookMessage, nil
}

func (h *ActionHandler) GetAllWebhookMessages(ctx context.Context) ([]*types.WebhookMessage, error) {
	var webhookMessages []*types.WebhookMessage
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		webhookMessages, err = h.d.GetAllWebhookMessagess(tx)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return webhookMessages, nil
}

func (h *ActionHandler) ValidateCreateWebhookMessageReq(ctx context.Context, req *CreateWebhookMessageRequest) error {
	if req.CommitSha == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("commit sha required"))
	}
	if req.CommitStatus == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("commit status required"))
	}
	if req.TargetURL == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("target url required"))
	}
	if _, err := url.ParseRequestURI(req.TargetURL); err != nil {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("target url %q", req.TargetURL))
	}
	if req.RepositoryPath == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("repository path required"))
	}
	if req.StatusContext == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("status context required"))
	}
	if req.IsCustom {
		if req.DestinationURL == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("destination url required"))
		}
		if req.ContentType == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("content type required"))
		}
	} else {
		if req.ProjectID == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project id required"))
		}
	}

	return nil
}

type CreateWebhookMessageRequest struct {
	IsCustom       bool
	ProjectID      string
	DestinationURL string
	ContentType    string
	Secret         string
	TargetURL      string
	CommitStatus   string
	Description    string
	RepositoryPath string
	CommitSha      string
	StatusContext  string
}

func (h *ActionHandler) CreateWebhookMessage(ctx context.Context, req *CreateWebhookMessageRequest) (*types.WebhookMessage, error) {
	if err := h.ValidateCreateWebhookMessageReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var webhookMessage *types.WebhookMessage
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		webhookMessage = types.NewWebhookMessage()
		webhookMessage.IsCustom = req.IsCustom
		webhookMessage.CommitSha = req.CommitSha
		webhookMessage.CommitStatus = req.CommitStatus
		webhookMessage.ContentType = &req.ContentType
		webhookMessage.Description = req.Description
		webhookMessage.DestinationURL = &req.DestinationURL
		webhookMessage.ProjectID = &req.ProjectID
		webhookMessage.RepositoryPath = req.RepositoryPath
		webhookMessage.Secret = &req.Secret
		webhookMessage.TargetURL = req.TargetURL
		webhookMessage.StatusContext = req.StatusContext

		if err := h.d.InsertWebhookMessage(tx, webhookMessage); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return webhookMessage, errors.WithStack(err)
}

func (h *ActionHandler) DeleteWebhookMessage(ctx context.Context, curWebhookMessageID string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check webhookmessage exists
		webhookmessage, err := h.d.GetWebhookMessage(tx, curWebhookMessageID)
		if err != nil {
			return errors.WithStack(err)
		}
		if webhookmessage == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("webhookmessage with id %q doesn't exists", curWebhookMessageID))
		}

		if err := h.d.DeleteWebhookMessage(tx, webhookmessage.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
