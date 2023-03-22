package types

import (
	"github.com/mitchellh/copystructure"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	stypes "agola.io/agola/services/types"
)

type Executor struct {
	sqlg.ObjectMeta

	// ExecutorID is the Executor unique id
	ExecutorID string `json:"executor_id,omitempty"`
	ListenURL  string `json:"listenURL,omitempty"`

	Archs []stypes.Arch `json:"archs,omitempty"`

	Labels map[string]string `json:"labels,omitempty"`

	AllowPrivilegedContainers bool `json:"allow_privileged_containers,omitempty"`

	ActiveTasksLimit int `json:"active_tasks_limit,omitempty"`
	ActiveTasks      int `json:"active_tasks,omitempty"`

	// Dynamic represents an executor that can be automatically removed since it's
	// part of a group of executors managing the same resources (i.e. a k8s
	// namespace managed by multiple executors that will automatically clean pods
	// owned of an old executor)
	Dynamic bool `json:"dynamic,omitempty"`

	// ExecutorGroup is the executor group which this executor belongs
	ExecutorGroup string `json:"executor_group,omitempty"`
	// SiblingExecutors are all the executors in the ExecutorGroup
	SiblingsExecutors []string `json:"siblings_executors,omitempty"`
}

func (e *Executor) DeepCopy() *Executor {
	ne, err := copystructure.Copy(e)
	if err != nil {
		panic(err)
	}
	return ne.(*Executor)
}

func NewExecutor(tx *sql.Tx) *Executor {
	return &Executor{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
