package lock

import (
	"context"

	"github.com/sorintlab/errors"
)

var ErrLocked = errors.New("already locked")

type LockFactory interface {
	NewLock(key string) Lock
}

type Lock interface {
	Lock(ctx context.Context) error
	TryLock(ctx context.Context) error
	Unlock() error
}
