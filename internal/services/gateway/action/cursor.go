package action

import (
	"encoding/base64"
	"encoding/json"

	"github.com/sorintlab/errors"

	util "agola.io/agola/internal/util"
)

func MarshalCursor(c any) (string, error) {
	cj, err := json.Marshal(c)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return base64.StdEncoding.EncodeToString(cj), nil
}

func UnmarshalCursor(cs string, c any) error {
	cj, err := base64.StdEncoding.DecodeString(cs)
	if err != nil {
		return util.NewAPIError(util.ErrBadRequest, err)
	}

	if err := json.Unmarshal(cj, c); err != nil {
		return util.NewAPIError(util.ErrBadRequest, err)
	}

	return nil
}

type StartCursor struct {
	Start string

	SortDirection SortDirection
}

type DeliveryCursor struct {
	StartSequence uint64

	SortDirection SortDirection

	DeliveryStatusFilter []string
}
