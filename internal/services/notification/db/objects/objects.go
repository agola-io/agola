package objects

import (
	"agola.io/agola/internal/sqlg"
)

const (
	Version = uint(4)
)

const TypesImport = "agola.io/agola/services/notification/types"

var AdditionalImports = []string{"time"}

var ObjectsInfo = []sqlg.ObjectInfo{
	{
		Name: "RunWebhook", Table: "runwebhook",
		Fields: []sqlg.ObjectField{
			{Name: "Payload", Type: "[]byte"},
			{Name: "ProjectID", Type: "string"},
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
	{
		// lastruneventsequence table contains the sequence of the last RunEvent managed by the notification service.
		// It must contain at most one row.
		// if in future we'll need to store multiple last sequences like this we could reuse it adding a specific key.
		Name: "LastRunEventSequence", Table: "lastruneventsequence",
		Fields: []sqlg.ObjectField{
			{Name: "Value", Type: "uint64"},
		},
	},
	{
		Name: "CommitStatus", Table: "commitstatus",
		Fields: []sqlg.ObjectField{
			{Name: "ProjectID", Type: "string"},
			{Name: "State", Type: "types.CommitState", BaseType: "string"},
			{Name: "CommitSHA", Type: "string"},
			{Name: "RunCounter", Type: "uint64"},
			{Name: "Description", Type: "string"},
			{Name: "Context", Type: "string"},
		},
	},
	{
		Name: "CommitStatusDelivery", Table: "commitstatusdelivery",
		Fields: []sqlg.ObjectField{
			{Name: "Sequence", Type: "uint64", Sequence: true},
			{Name: "CommitStatusID", Type: "string"},
			{Name: "DeliveryStatus", Type: "types.DeliveryStatus", BaseType: "string"},
			{Name: "DeliveredAt", Type: "time.Time", Nullable: true},
		},
		Constraints: []string{
			"foreign key (commit_status_id) references commitstatus(id)",
		},
		Indexes: []string{
			"create index if not exists commitstatusdelivery_sequence_idx on commitstatusdelivery(sequence)",
		},
	},
}
