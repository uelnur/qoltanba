package jobs

import (
	"context"
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bucketName holds every job keyed by id. One flat bucket is enough: lookups are
// by id and the full scans (recover/reap) are startup/periodic, not hot paths.
var bucketName = []byte("jobs")

// BoltStore is the durable on-disk Store: a single bbolt file (pure Go, no
// external broker) that lets in-flight jobs survive a single-node restart. The
// file holds request payloads that may contain secrets, so it is created 0600.
type BoltStore struct {
	db *bolt.DB
}

var _ Store = (*BoltStore)(nil)

// OpenBoltStore opens (or creates) the bbolt database at path with 0600
// permissions and ensures the jobs bucket exists.
func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketName)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Create(_ context.Context, j *Job) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b.Get([]byte(j.ID)) != nil {
			return ErrExists
		}
		return put(b, j)
	})
}

func (s *BoltStore) Get(_ context.Context, id string) (*Job, error) {
	var j *Job
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketName).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var out Job
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		j = &out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}

func (s *BoltStore) Save(_ context.Context, j *Job) error {
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx.Bucket(bucketName), j) })
}

func (s *BoltStore) Delete(_ context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Delete([]byte(id)) })
}

func (s *BoltStore) Recover(_ context.Context) ([]string, error) {
	var queued []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(k, raw []byte) error {
			var j Job
			if err := json.Unmarshal(raw, &j); err != nil {
				return err
			}
			if j.Status == StatusRunning {
				j.Status = StatusQueued
				if err := put(b, &j); err != nil {
					return err
				}
			}
			if j.Status == StatusQueued {
				queued = append(queued, j.ID)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return queued, nil
}

func (s *BoltStore) Reap(_ context.Context, now time.Time) (int, error) {
	var expired [][]byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := b.ForEach(func(k, raw []byte) error {
			var j Job
			if err := json.Unmarshal(raw, &j); err != nil {
				return err
			}
			if j.Status.Terminal() && j.ExpiresAt != nil && !j.ExpiresAt.After(now) {
				expired = append(expired, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return len(expired), err
}

func (s *BoltStore) Close() error { return s.db.Close() }

// put marshals a job and stores it under its id.
func put(b *bolt.Bucket, j *Job) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return b.Put([]byte(j.ID), raw)
}
