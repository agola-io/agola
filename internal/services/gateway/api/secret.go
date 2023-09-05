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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

func createSecretResponse(s *csapitypes.Secret) *gwapitypes.SecretResponse {
	return &gwapitypes.SecretResponse{
		ID:         s.ID,
		Name:       s.Name,
		ParentPath: s.ParentPath,
	}
}

type SecretsCursor struct {
	LastSecretName   string
	Asc              bool
	Tree             bool
	RemoveOverridden bool
}

type SecretHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewSecretHandler(log zerolog.Logger, ah *action.ActionHandler) *SecretHandler {
	return &SecretHandler{log: log, ah: ah}
}

func (h *SecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	cursorS := query.Get("cursor")
	var start string
	var asc bool
	var tree bool
	var removeoverridden bool

	if cursorS != "" {
		decodedCursor, err := base64.StdEncoding.DecodeString(cursorS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot decode cursor")))
			return
		}

		var cursor SecretsCursor
		if err := json.Unmarshal(decodedCursor, &cursor); err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot unmarshal cursor")))
			return
		}

		start = cursor.LastSecretName
		asc = cursor.Asc
		tree = cursor.Tree
		removeoverridden = cursor.RemoveOverridden
	} else {
		if _, ok := query["asc"]; ok {
			asc = true
		}

		start = query.Get("start")

		_, tree = query["tree"]
		_, removeoverridden = query["removeoverridden"]
	}

	var limit int
	limitS := query.Get("limit")
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("limit must be greater or equal than 0")))
		return
	}

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	areq := &action.GetSecretsRequest{
		ParentType:       parentType,
		ParentRef:        parentRef,
		Start:            start,
		Asc:              asc,
		Limit:            limit,
		Tree:             tree,
		RemoveOverridden: removeoverridden,
	}
	cssecrets, err := h.ah.GetSecrets(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	cursorS = ""
	if cssecrets.HasMoreData {
		cursor := SecretsCursor{
			LastSecretName:   cssecrets.Secrets[limit-1].Name,
			Asc:              asc,
			Tree:             tree,
			RemoveOverridden: removeoverridden,
		}
		serializedCursor, err := json.Marshal(&cursor)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrInternal, errors.Wrapf(err, "cannot marshal cursor")))
			return
		}
		cursorS = base64.StdEncoding.EncodeToString(serializedCursor)
	}

	secrets := make([]*gwapitypes.SecretResponse, len(cssecrets.Secrets))
	for i, s := range cssecrets.Secrets {
		secrets[i] = createSecretResponse(s)
	}

	response := &gwapitypes.SecretsResponse{
		Secrets: secrets,
		Cursor:  cursorS,
	}
	if err := util.HTTPResponse(w, http.StatusOK, response); err != nil {
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
	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		return
	}

	var req gwapitypes.CreateSecretRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateSecretRequest{
		Name:             req.Name,
		ParentType:       parentType,
		ParentRef:        parentRef,
		Type:             cstypes.SecretType(req.Type),
		Data:             req.Data,
		SecretProviderID: req.SecretProviderID,
		Path:             req.Path,
	}
	cssecret, err := h.ah.CreateSecret(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createSecretResponse(cssecret)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
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

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	var req gwapitypes.UpdateSecretRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}
	areq := &action.UpdateSecretRequest{
		SecretName: secretName,

		Name:             req.Name,
		ParentType:       parentType,
		ParentRef:        parentRef,
		Type:             cstypes.SecretType(req.Type),
		Data:             req.Data,
		SecretProviderID: req.SecretProviderID,
		Path:             req.Path,
	}
	cssecret, err := h.ah.UpdateSecret(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createSecretResponse(cssecret)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
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

	parentType, parentRef, err := GetConfigTypeRef(r)
	if util.HTTPError(w, err) {
		return
	}

	err = h.ah.DeleteSecret(ctx, parentType, parentRef, secretName)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
