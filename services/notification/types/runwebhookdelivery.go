package types

import (
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type DeliveryStatus string

const (
	DeliveryStatusNotDelivered  DeliveryStatus = "notDelivered"
	DeliveryStatusDelivered     DeliveryStatus = "delivered"
	DeliveryStatusDeliveryError DeliveryStatus = "deliveryError"
)

func DeliveryStatusFromStringSlice(slice []string) ([]DeliveryStatus, error) {
	dss := make([]DeliveryStatus, len(slice))
	for i, s := range slice {
		val := DeliveryStatus(s)
		switch val {
		case DeliveryStatusNotDelivered, DeliveryStatusDelivered, DeliveryStatusDeliveryError:
			dss[i] = val
		default:
			return nil, errors.Errorf("invalid delivery status %q", val)
		}
	}
	return dss, nil
}

type RunWebhookDelivery struct {
	sqlg.ObjectMeta

	Sequence uint64 `json:"sequence"`

	RunWebhookID   string         `json:"run_webhook_id"`
	DeliveryStatus DeliveryStatus `json:"delivery_status"`
	DeliveredAt    *time.Time     `json:"delivered_at"`
	StatusCode     int            `json:"status_code"`
}

func NewRunWebhookDelivery(tx *sql.Tx) *RunWebhookDelivery {
	return &RunWebhookDelivery{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
