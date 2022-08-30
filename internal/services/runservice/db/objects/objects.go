package objects

import (
	idb "agola.io/agola/internal/db"
)

var ObjectsInfo = []idb.ObjectInfo{
	{Name: "Sequence", Table: "sequence_t"},
	{Name: "ChangeGroup", Table: "changegroup"},
	{Name: "Run", Table: "run"},
	{Name: "RunConfig", Table: "runconfig"},
	{Name: "RunCounter", Table: "runcounter"},
	{Name: "RunEvent", Table: "runevent"},
	{Name: "Executor", Table: "executor"},
	{Name: "ExecutorTask", Table: "executortask"},
}
