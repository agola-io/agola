// Copyright 2019 Sorint.lab
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

package etcd

import (
	"context"
	"crypto/tls"
	"net/url"
	"strconv"
	"strings"
	"time"

	"agola.io/agola/internal/util"

	"go.etcd.io/etcd/clientv3"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/namespace"
	"go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

var (
	// ErrKeyNotFound is thrown when the key is not found in the store during a Get operation
	ErrKeyNotFound = errors.New("key not found")
	ErrKeyModified = errors.New("unable to complete atomic operation, key modified")
)

const (
	defaultEndpoints = "http://127.0.0.1:2379"

	compactKey                = "compactkey"
	defaultCompactionInterval = 10 * time.Minute
)

type WriteOptions struct {
	TTL time.Duration
}

type Config struct {
	Logger        *zap.Logger
	Endpoints     string
	Prefix        string
	CertFile      string
	KeyFile       string
	CAFile        string
	SkipTLSVerify bool

	CompactionInterval time.Duration
}

func FromEtcdError(err error) error {
	switch err {
	case rpctypes.ErrKeyNotFound:
		return ErrKeyNotFound
	}
	return err
}

type Store struct {
	log *zap.SugaredLogger
	c   *etcdclientv3.Client
}

func New(cfg Config) (*Store, error) {
	prefix := cfg.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	endpointsStr := cfg.Endpoints
	if endpointsStr == "" {
		endpointsStr = defaultEndpoints
	}
	endpoints := strings.Split(endpointsStr, ",")

	// check that all the endpoints have the same scheme
	var scheme string
	for _, e := range endpoints {
		u, err := url.Parse(e)
		if err != nil {
			return nil, errors.Errorf("cannot parse endpoint %q: %w", e, err)
		}
		if scheme == "" {
			scheme = u.Scheme
		}
		if scheme != u.Scheme {
			return nil, errors.Errorf("all the endpoints must have the same scheme")
		}
	}

	var tlsConfig *tls.Config
	if scheme != "http" && scheme != "https" {
		return nil, errors.Errorf("endpoints scheme must be http or https")
	}
	if scheme == "https" {
		var err error
		tlsConfig, err = util.NewTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, cfg.SkipTLSVerify)
		if err != nil {
			return nil, errors.Errorf("cannot create tls config: %w", err)
		}
	}

	config := etcdclientv3.Config{
		Endpoints: endpoints,
		TLS:       tlsConfig,
	}

	c, err := etcdclientv3.New(config)
	if err != nil {
		return nil, err
	}

	c.KV = namespace.NewKV(c.KV, prefix)
	c.Watcher = namespace.NewWatcher(c.Watcher, prefix)
	c.Lease = namespace.NewLease(c.Lease, prefix)

	s := &Store{
		log: cfg.Logger.Sugar(),
		c:   c,
	}

	compactionInterval := defaultCompactionInterval
	if cfg.CompactionInterval != 0 {
		compactionInterval = cfg.CompactionInterval
	}
	go s.compactor(context.TODO(), compactionInterval)

	return s, nil
}

func (s *Store) Client() *etcdclientv3.Client {
	return s.c
}

func (s *Store) Put(ctx context.Context, key string, value []byte, options *WriteOptions) (*etcdclientv3.PutResponse, error) {
	etcdv3Options := []etcdclientv3.OpOption{}
	if options != nil {
		if options.TTL > 0 {
			lease, err := s.c.Grant(ctx, int64(options.TTL.Seconds()))
			if err != nil {
				return nil, err
			}
			etcdv3Options = append(etcdv3Options, etcdclientv3.WithLease(lease.ID))
		}
	}
	resp, err := s.c.Put(ctx, key, string(value), etcdv3Options...)

	return resp, FromEtcdError(err)
}

func (s *Store) Get(ctx context.Context, key string, revision int64) (*etcdclientv3.GetResponse, error) {
	opts := []etcdclientv3.OpOption{}
	if revision != 0 {
		opts = append(opts, etcdclientv3.WithRev(revision))
	}

	resp, err := s.c.Get(ctx, key, opts...)
	if err != nil {
		return resp, FromEtcdError(err)
	}
	if len(resp.Kvs) == 0 {
		return resp, ErrKeyNotFound
	}

	return resp, nil
}

func (s *Store) List(ctx context.Context, directory, start string, revision int64) (*etcdclientv3.GetResponse, error) {
	if !strings.HasSuffix(directory, "/") {
		directory += "/"
	}
	key := directory
	rangeEnd := clientv3.GetPrefixRangeEnd(key)

	if start != "" {
		key = start
	}

	opts := []etcdclientv3.OpOption{etcdclientv3.WithRange(rangeEnd)}
	if revision != 0 {
		opts = append(opts, etcdclientv3.WithRev(revision))
	}

	resp, err := s.c.Get(ctx, key, opts...)

	return resp, FromEtcdError(err)
}

type ListPagedResp struct {
	Resp         *clientv3.GetResponse
	HasMore      bool
	Continuation *ListPagedContinuation
}

type ListPagedContinuation struct {
	Revision int64
	LastKey  string
}

func (s *Store) ListPaged(ctx context.Context, directory string, revision, limit int64, continuation *ListPagedContinuation) (*ListPagedResp, error) {
	if !strings.HasSuffix(directory, "/") {
		directory += "/"
	}
	key := directory
	rangeEnd := clientv3.GetPrefixRangeEnd(key)

	if continuation != nil {
		revision = continuation.Revision
		key = continuation.LastKey
	}

	opts := []etcdclientv3.OpOption{etcdclientv3.WithRange(rangeEnd), etcdclientv3.WithLimit(limit)}
	if revision != 0 {
		opts = append(opts, etcdclientv3.WithRev(revision))
	}

	resp, err := s.c.Get(ctx, key, opts...)
	if err != nil {
		return nil, FromEtcdError(err)
	}

	lastKey := key
	if len(resp.Kvs) > 0 {
		lastKey = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	return &ListPagedResp{
		Resp:    resp,
		HasMore: resp.More,
		Continuation: &ListPagedContinuation{
			Revision: resp.Header.Revision,
			LastKey:  lastKey,
		},
	}, nil
}

func (s *Store) AtomicPut(ctx context.Context, key string, value []byte, prevRevision int64, options *WriteOptions) (*etcdclientv3.TxnResponse, error) {
	etcdv3Options := []etcdclientv3.OpOption{}
	if options != nil {
		if options.TTL > 0 {
			lease, err := s.c.Grant(ctx, int64(options.TTL))
			if err != nil {
				return nil, err
			}
			etcdv3Options = append(etcdv3Options, etcdclientv3.WithLease(lease.ID))
		}
	}
	var cmp etcdclientv3.Cmp
	if prevRevision != 0 {
		cmp = etcdclientv3.Compare(etcdclientv3.ModRevision(key), "=", int64(prevRevision))
	} else {
		// key must not exist
		cmp = etcdclientv3.Compare(etcdclientv3.CreateRevision(key), "=", 0)
	}

	txn := s.c.Txn(ctx).If(cmp)
	txn = txn.Then(etcdclientv3.OpPut(key, string(value), etcdv3Options...))
	tresp, err := txn.Commit()

	if err != nil {
		return tresp, FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return tresp, ErrKeyModified
	}

	return tresp, nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.c.Delete(ctx, key)

	return err
}

func (s *Store) DeletePrefix(ctx context.Context, prefix string) error {
	etcdv3Options := []clientv3.OpOption{}

	key := prefix
	if len(key) == 0 {
		key = "\x00"
		etcdv3Options = append(etcdv3Options, clientv3.WithFromKey())
	} else {
		etcdv3Options = append(etcdv3Options, clientv3.WithPrefix())
	}

	_, err := s.c.Delete(ctx, key, etcdv3Options...)

	return err
}

func (s *Store) AtomicDelete(ctx context.Context, key string, revision int64) (*etcdclientv3.TxnResponse, error) {
	cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(key), "=", revision)
	req := etcdclientv3.OpDelete(key)

	tresp, err := s.c.Txn(ctx).If(cmp).Then(req).Commit()

	if err != nil {
		return tresp, FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return tresp, ErrKeyModified
	}
	return tresp, nil
}

func (s *Store) WatchKey(ctx context.Context, prefix string, revision int64) etcdclientv3.WatchChan {
	etcdv3Options := []etcdclientv3.OpOption{}
	if revision != 0 {
		etcdv3Options = append(etcdv3Options, etcdclientv3.WithRev(revision))
	}
	return s.c.Watch(ctx, prefix, etcdv3Options...)
}

func (s *Store) Watch(ctx context.Context, prefix string, revision int64) etcdclientv3.WatchChan {
	etcdv3Options := []etcdclientv3.OpOption{clientv3.WithPrefix()}
	if revision != 0 {
		etcdv3Options = append(etcdv3Options, etcdclientv3.WithRev(revision))
	}
	return s.c.Watch(ctx, prefix, etcdv3Options...)
}

func (s *Store) Close() error {
	return s.c.Close()
}

func (s *Store) compactor(ctx context.Context, interval time.Duration) {
	var version int64
	var rev int64
	var err error
	for {
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return
		}

		version, rev, err = s.compact(ctx, version, rev)
		if err != nil {
			continue
		}
	}
}

func (s *Store) compact(ctx context.Context, version, rev int64) (int64, int64, error) {
	resp, err := s.c.KV.Txn(ctx).If(
		clientv3.Compare(clientv3.Version(compactKey), "=", version),
	).Then(
		clientv3.OpPut(compactKey, strconv.FormatInt(rev, 10)),
	).Else(
		clientv3.OpGet(compactKey),
	).Commit()

	if err != nil {
		return version, rev, err
	}

	curRev := resp.Header.Revision

	if !resp.Succeeded {
		curVersion := resp.Responses[0].GetResponseRange().Kvs[0].Version
		return curVersion, curRev, nil
	}
	curVersion := version + 1

	if rev == 0 {
		return curVersion, curRev, nil
	}
	if _, err = s.c.Compact(ctx, rev); err != nil {
		s.log.Warnf("compact error: %v", err)
		return curVersion, curRev, err
	}
	s.log.Infof("compacted revision: %d", rev)
	return curVersion, curRev, nil
}
