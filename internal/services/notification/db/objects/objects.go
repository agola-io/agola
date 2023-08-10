package objects

import (
	"agola.io/agola/internal/sqlg"
)

const (
	Version = uint(1)
)

const TypesImport = "agola.io/agola/services/notification/types"

var AdditionalImports = []string{"time"}

var ObjectsInfo = []sqlg.ObjectInfo{
	{
		Name: "RunWebhook", Table: "runwebhook",
		Fields: []sqlg.ObjectField{
			{Name: "Payload", Type: "[]byte"},
		},
	},
	{
		Name: "RunWebhookDelivery", Table: "runwebhookdelivery",
		Fields: []sqlg.ObjectField{
			{Name: "Sequence", Type: "uint64", Sequence: true},
			{Name: "RunWebhookID", Type: "string"},
			{Name: "DeliveryStatus", Type: "types.DeliveryStatus", BaseType: "string"},
			{Name: "DeliveredAt", Type: "time.Time", Nullable: true},
			{Name: "StatusCode", Type: "int"},
		},
		Constraints: []string{
			"foreign key (run_webhook_id) references runwebhook(id)",
		},
		Indexes: []string{
			"create index if not exists runwebhookdelivery_sequence_idx on runwebhookdelivery(sequence)",
		},
	},
}
