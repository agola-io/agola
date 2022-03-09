package lock

import (
	"context"
	stdsql "database/sql"
	"hash/fnv"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"
)

type PGLockFactory struct {
	db *sql.DB
}

func NewPGLockFactory(db *sql.DB) *PGLockFactory {
	return &PGLockFactory{db: db}
}

func (l *PGLockFactory) NewLock(key string) Lock {
	return NewPGLock(l.db, key)
}

type PGLock struct {
	db  *sql.DB
	key int64
	c   *stdsql.Conn
}

func NewPGLock(db *sql.DB, key string) *PGLock {
	return &PGLock{db: db, key: hash(key)}
}

func (l *PGLock) Lock(ctx context.Context) error {
	if l.c != nil {
		panic("db connection isn't nil")
	}
	c, err := l.db.Conn(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = c.ExecContext(ctx, "select pg_advisory_lock($1)", l.key)
	if err != nil {
		c.Close()
		return errors.WithStack(err)
	}
	l.c = c
	return nil

}

func (l *PGLock) TryLock(ctx context.Context) error {
	if l.c != nil {
		panic("db connection isn't nil")
	}
	c, err := l.db.Conn(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	var ok bool
	rows, err := c.QueryContext(ctx, "select pg_try_advisory_lock($1)", l.key)
	if err != nil {
		c.Close()
		return errors.WithStack(err)
	}

	if rows.Next() {
		if err := rows.Scan(&ok); err != nil {
			return errors.Wrap(err, "failed to scan rows")
		}
	}
	if err := rows.Err(); err != nil {
		c.Close()
		return errors.WithStack(err)
	}
	rows.Close()

	if !ok {
		c.Close()
		return ErrLocked
	}

	l.c = c
	return nil

}

func (l *PGLock) Unlock() error {
	if l.c == nil {
		panic("db connection is nil")
	}
	_, _ = l.c.ExecContext(context.Background(), "select pg_advisory_unlock($1)", l.key)
	_ = l.c.Close()
	l.c = nil
	return nil
}

func hash(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}
