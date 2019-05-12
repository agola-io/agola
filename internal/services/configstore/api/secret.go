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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// Secret augments types.Secret with dynamic data
type Secret struct {
	*types.Secret

	// dynamic data
	ParentPath string
}

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

	resSecrets := make([]*Secret, len(secrets))
	for i, s := range secrets {
		resSecrets[i] = &Secret{Secret: s}
	}

	err = h.readDB.Do(func(tx *db.Tx) error {
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
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
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
