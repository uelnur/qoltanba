package oidc

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ChallengeStore persists issued challenges between the challenge and verify
// calls. Consume is the anti-replay seam: it atomically fetches a challenge and
// marks it used, so a second verify with the same id is rejected. Expiry is
// enforced by the caller (which holds the clock); Reap removes expired entries.
type ChallengeStore interface {
	Create(ctx context.Context, c *Challenge) error
	// Consume atomically returns the challenge and marks it used. It returns
	// ErrChallengeNotFound if absent and ErrChallengeUsed if already consumed.
	Consume(ctx context.Context, id string) (*Challenge, error)
	Reap(ctx context.Context, now time.Time) (int, error)
	// Len reports the number of stored challenges, for the metrics gauge.
	Len() int
	Close() error
}

// cloneChallenge deep-copies a challenge so stored state never aliases a caller's
// value (and vice versa).
func cloneChallenge(c *Challenge) *Challenge {
	cp := *c
	cp.Nonce = append([]byte(nil), c.Nonce...)
	return &cp
}

// MemStore is the ephemeral in-memory ChallengeStore: fast, zero-dependency, the
// default. Challenges do not survive a restart — fine, since their TTL is short
// (minutes) and an in-flight login simply retries.
type MemStore struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
}

var _ ChallengeStore = (*MemStore)(nil)

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{challenges: make(map[string]*Challenge)} }

func (s *MemStore) Create(_ context.Context, c *Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ID] = cloneChallenge(c)
	return nil
}

func (s *MemStore) Consume(_ context.Context, id string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	if c.Used {
		return nil, ErrChallengeUsed
	}
	c.Used = true
	return cloneChallenge(c), nil
}

func (s *MemStore) Reap(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.challenges {
		if !c.ExpiresAt.After(now) {
			delete(s.challenges, id)
			n++
		}
	}
	return n, nil
}

func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.challenges)
}

func (s *MemStore) Close() error { return nil }

// challengeBucket holds every challenge keyed by id.
var challengeBucket = []byte("challenges")

// BoltStore is the durable on-disk ChallengeStore: a single bbolt file (pure Go,
// no external broker) so challenges survive a restart and can be shared across a
// single node. The file may hold client nonces, so it is created 0600.
type BoltStore struct {
	db *bolt.DB
}

var _ ChallengeStore = (*BoltStore)(nil)

// OpenBoltStore opens (or creates) the bbolt database at path with 0600
// permissions and ensures the challenges bucket exists.
func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(challengeBucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Create(_ context.Context, c *Challenge) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		return tx.Bucket(challengeBucket).Put([]byte(c.ID), raw)
	})
}

func (s *BoltStore) Consume(_ context.Context, id string) (*Challenge, error) {
	var out *Challenge
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(challengeBucket)
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrChallengeNotFound
		}
		var c Challenge
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.Used {
			return ErrChallengeUsed
		}
		c.Used = true
		updated, err := json.Marshal(&c)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(id), updated); err != nil {
			return err
		}
		out = &c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BoltStore) Reap(_ context.Context, now time.Time) (int, error) {
	var expired [][]byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(challengeBucket)
		if err := b.ForEach(func(k, raw []byte) error {
			var c Challenge
			if err := json.Unmarshal(raw, &c); err != nil {
				return err
			}
			if !c.ExpiresAt.After(now) {
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

func (s *BoltStore) Len() int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(challengeBucket).Stats().KeyN
		return nil
	})
	return n
}

func (s *BoltStore) Close() error { return s.db.Close() }
