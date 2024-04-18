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

package types

import "time"

type DeliveryStatus string

const (
	DeliveryStatusNotDelivered  DeliveryStatus = "notDelivered"
	DeliveryStatusDelivered     DeliveryStatus = "delivered"
	DeliveryStatusDeliveryError DeliveryStatus = "deliveryError"
)

type RunWebhookDeliveryResponse struct {
	ID             string         `json:"id"`
	Sequence       uint64         `json:"sequence"`
	DeliveryStatus DeliveryStatus `json:"delivery_status"`
	DeliveredAt    *time.Time     `json:"delivered_at"`
	StatusCode     int            `json:"status_code"`
}
