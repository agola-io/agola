package lock

import (
	"context"
	"sync"

	"agola.io/agola/internal/errors"
	"golang.org/x/sync/semaphore"
)

type LocalLocks struct {
	locks map[string]*semaphore.Weighted
	m     sync.Mutex
}

func NewLocalLocks() *LocalLocks {
	return &LocalLocks{locks: make(map[string]*semaphore.Weighted)}
}

func (ll *LocalLocks) lock(ctx context.Context, key string) error {
	ll.m.Lock()
	l, ok := ll.locks[key]
	if !ok {
		l = semaphore.NewWeighted(1)
		ll.locks[key] = l
	}
	ll.m.Unlock()
	return errors.WithStack(l.Acquire(ctx, 1))
}

func (ll *LocalLocks) tryLock(ctx context.Context, key string) error {
	ll.m.Lock()
	l, ok := ll.locks[key]
	if !ok {
		l = semaphore.NewWeighted(1)
		ll.locks[key] = l
	}
	ll.m.Unlock()

	ok = l.TryAcquire(1)
	if !ok {
		return ErrLocked
	}
	return nil
}

func (ll *LocalLocks) unlock(key string) {
	ll.m.Lock()
	l, ok := ll.locks[key]
	if !ok {
		panic(errors.Errorf("no mutex for key: %s", key))
	}
	ll.m.Unlock()
	l.Release(1)
}

type LocalLockFactory struct {
	ll *LocalLocks
}

func NewLocalLockFactory(ll *LocalLocks) *LocalLockFactory {
	return &LocalLockFactory{ll: ll}
}

func (l *LocalLockFactory) NewLock(key string) Lock {
	return &LocalLock{ll: l.ll, key: key}
}

type LocalLock struct {
	ll  *LocalLocks
	key string
}

func (l *LocalLock) Lock(ctx context.Context) error {
	return l.ll.lock(ctx, l.key)

}

func (l *LocalLock) TryLock(ctx context.Context) error {
	return l.ll.tryLock(ctx, l.key)
}

func (l *LocalLock) Unlock() error {
	l.ll.unlock(l.key)
	return nil
}
