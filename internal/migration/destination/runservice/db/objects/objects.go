package objects

import (
	"agola.io/agola/internal/sqlg"
)

const (
	Version = uint(1)
)

const TypesImport = "agola.io/agola/services/runservice/types"

var AdditionalImports = []string{"time"}

var ObjectsInfo = []sqlg.ObjectInfo{
	{Name: "ChangeGroup", Table: "changegroup",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Value", Type: "string"},
		},
	},
	{Name: "RunConfig", Table: "runconfig",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Group", ColName: "run_group", Type: "string"},
			{Name: "SetupErrors", Type: "[]string", JSON: true},
			{Name: "Annotations", Type: "map[string]string", JSON: true},
			{Name: "StaticEnvironment", Type: "map[string]string", JSON: true},
			{Name: "Environment", Type: "map[string]string", JSON: true},
			{Name: "Tasks", Type: "map[string]*types.RunConfigTask", JSON: true},
			{Name: "CacheGroup", Type: "string"},
		},
	},
	{Name: "Run", Table: "run",
		Fields: []sqlg.ObjectField{
			{Name: "Sequence", Type: "uint64", Sequence: true},
			{Name: "Name", Type: "string"},
			{Name: "RunConfigID", Type: "string"},
			{Name: "Counter", Type: "uint64"},
			{Name: "Group", ColName: "run_group", Type: "string"},
			{Name: "Annotations", Type: "map[string]string", JSON: true},
			{Name: "Phase", Type: "types.RunPhase", BaseType: "string"},
			{Name: "Result", Type: "types.RunResult", BaseType: "string"},
			{Name: "Stop", Type: "bool"},
			{Name: "Tasks", Type: "map[string]*RunTask", JSON: true},
			{Name: "EnqueueTime", Type: "time.Time", Nullable: true},
			{Name: "StartTime", Type: "time.Time", Nullable: true},
			{Name: "EndTime", Type: "time.Time", Nullable: true},
			{Name: "Archived", Type: "bool"},
		},
		Indexes: []string{
			"create index if not exists run_group_idx on run(run_group)",
		},
		Constraints: []string{
			"foreign key (run_config_id) references runconfig(id)",
		},
	},
	{Name: "RunCounter", Table: "runcounter",
		Fields: []sqlg.ObjectField{
			{Name: "GroupID", Type: "string", Unique: true},
			{Name: "Value", Type: "uint64"},
		},
		Indexes: []string{
			"create index if not exists runcounter_group_id_idx on runcounter(group_id)",
		},
	},
	{Name: "RunEvent", Table: "runevent",
		Fields: []sqlg.ObjectField{
			{Name: "Sequence", Type: "uint64", Sequence: true},
			{Name: "RunID", Type: "string"},
			{Name: "Phase", Type: "types.RunPhase", BaseType: "string"},
			{Name: "Result", Type: "types.RunResult", BaseType: "string"},
		},
	},
	{Name: "Executor", Table: "executor",
		Fields: []sqlg.ObjectField{
			{Name: "ExecutorID", Type: "string"},
			{Name: "ListenURL", Type: "string"},
			{Name: "Archs", Type: "[]stypes.Arch", JSON: true},
			{Name: "Labels", Type: "map[string]string", JSON: true},
			{Name: "AllowPrivilegedContainers", Type: "bool"},
			{Name: "ActiveTasksLimit", Type: "int"},
			{Name: "ActiveTasks", Type: "int"},
			{Name: "Dynamic", Type: "bool"},
			{Name: "ExecutorGroup", Type: "string"},
			{Name: "SiblingsExecutors", Type: "[]string", JSON: true},
		},
	},
	{Name: "ExecutorTask", Table: "executortask",
		Fields: []sqlg.ObjectField{
			{Name: "ExecutorID", Type: "string"},
			{Name: "RunID", Type: "string"},
			{Name: "RunTaskID", Type: "string"},
			{Name: "Stop", Type: "bool"},
			{Name: "Phase", Type: "types.ExecutorTaskPhase", BaseType: "string"},
			{Name: "Timedout", Type: "bool"},
			{Name: "FailError", Type: "string"},
			{Name: "StartTime", Type: "time.Time", Nullable: true},
			{Name: "EndTime", Type: "time.Time", Nullable: true},
			{Name: "SetupStep", Type: "types.ExecutorTaskStepStatus", JSON: true},
			{Name: "Steps", Type: "[]*types.ExecutorTaskStepStatus", JSON: true},
		},
	},
}
