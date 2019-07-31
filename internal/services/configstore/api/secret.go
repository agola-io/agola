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

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type SecretHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewSecretHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *SecretHandler {
	return &SecretHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *SecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretID := vars["secretid"]

	secret, err := h.ah.GetSecret(ctx, secretID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, secret); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type SecretsHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewSecretsHandler(logger *zap.Logger, ah *action.ActionHandler, readDB *readdb.ReadDB) *SecretsHandler {
	return &SecretsHandler{log: logger.Sugar(), ah: ah, readDB: readDB}
}

func (h *SecretsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	_, tree := query["tree"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	secrets, err := h.ah.GetSecrets(ctx, parentType, parentRef, tree)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resSecrets := make([]*csapitypes.Secret, len(secrets))
	for i, s := range secrets {
		resSecrets[i] = &csapitypes.Secret{Secret: s}
	}

	err = h.readDB.Do(ctx, func(tx *db.Tx) error {
		// populate parent path
		for _, s := range resSecrets {
			pp, err := h.readDB.GetPath(tx, s.Parent.Type, s.Parent.ID)
			if err != nil {
				return err
			}
			s.ParentPath = pp
		}
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := httpResponse(w, http.StatusOK, resSecrets); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateSecretHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateSecretHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateSecretHandler {
	return &CreateSecretHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var secret *types.Secret
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&secret); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	secret.Parent.Type = parentType
	secret.Parent.ID = parentRef

	secret, err = h.ah.CreateSecret(ctx, secret)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, secret); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateSecretHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateSecretHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateSecretHandler {
	return &UpdateSecretHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretName := vars["secretname"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	var secret *types.Secret
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&secret); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	secret.Parent.Type = parentType
	secret.Parent.ID = parentRef

	areq := &action.UpdateSecretRequest{
		SecretName: secretName,
		Secret:     secret,
	}
	secret, err = h.ah.UpdateSecret(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, secret); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteSecretHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteSecretHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteSecretHandler {
	return &DeleteSecretHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	secretName := vars["secretname"]

	parentType, parentRef, err := GetConfigTypeRef(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	err = h.ah.DeleteSecret(ctx, parentType, parentRef, secretName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
