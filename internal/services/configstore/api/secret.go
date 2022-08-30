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

package api

import (
	"encoding/json"
	"net/http"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type SecretHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
	d   *db.DB
}

func NewSecretHandler(log zerolog.Logger, ah *action.ActionHandler, d *db.DB) *SecretHandler {
	return &SecretHandler{log: log, ah: ah, d: d}
}

func (h *SecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretID := vars["secretid"]

	secret, err := h.ah.GetSecret(ctx, secretID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, secret); err != nil {
		h.log.Err(err).Send()
	}
}

type SecretsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
	d   *db.DB
}

func NewSecretsHandler(log zerolog.Logger, ah *action.ActionHandler, d *db.DB) *SecretsHandler {
	return &SecretsHandler{log: log, ah: ah, d: d}
}

func (h *SecretsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	secrets, err := h.ah.GetSecrets(ctx, parentKind, parentRef, tree)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resSecrets := make([]*csapitypes.Secret, len(secrets))
	for i, s := range secrets {
		resSecrets[i] = &csapitypes.Secret{Secret: s}
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		// populate parent path
		for _, s := range resSecrets {
			pp, err := h.d.GetPath(tx, s.Parent.Kind, s.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			s.ParentPath = pp
		}
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, resSecrets); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateSecretHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateSecretHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateSecretHandler {
	return &CreateSecretHandler{log: log, ah: ah}
}

func (h *CreateSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentKind, parentRef, err := GetObjectKindRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var req *csapitypes.CreateUpdateSecretRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateSecretRequest{
		Name: req.Name,
		Parent: types.Parent{
			Kind: parentKind,
			ID:   parentRef,
		},
		Type:             req.Type,
		Data:             req.Data,
		SecretProviderID: req.SecretProviderID,
		Path:             req.Path,
	}

	secret, err := h.ah.CreateSecret(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, secret); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateSecretHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateSecretHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateSecretHandler {
	return &UpdateSecretHandler{log: log, ah: ah}
}

func (h *UpdateSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretName := vars["secretname"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var req *csapitypes.CreateUpdateSecretRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateUpdateSecretRequest{
		Name: req.Name,
		Parent: types.Parent{
			Kind: parentKind,
			ID:   parentRef,
		},
		Type:             req.Type,
		Data:             req.Data,
		SecretProviderID: req.SecretProviderID,
		Path:             req.Path,
	}

	secret, err := h.ah.UpdateSecret(ctx, secretName, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, secret); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteSecretHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteSecretHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteSecretHandler {
	return &DeleteSecretHandler{log: log, ah: ah}
}

func (h *DeleteSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretName := vars["secretname"]

	parentKind, parentRef, err := GetObjectKindRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	err = h.ah.DeleteSecret(ctx, parentKind, parentRef, secretName)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
