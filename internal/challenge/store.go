// Package challenge is the anti-replay challenge–response primitive: the service
// issues a single-use nonce with a TTL, the user signs it with their ЭЦП, and the
// service verifies that signature and reports who signed.
//
// It exists on its own because the flow is not specific to login. Confirming a
// payment, an approval or a consent needs exactly the same handshake, and it was
// previously reachable only through the OIDC grant. The OIDC provider now builds
// on this package rather than owning it.
package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Challenge is one issued nonce awaiting a signature.
type Challenge struct {
	ID    string `json:"id"`
	Nonce []byte `json:"nonce"`
	// Purpose is a free-form label of what signing this nonce means ("login",
	// "payment.confirm"). It travels back to the caller on confirmation so the
	// signature cannot be repurposed for a different action than it was issued for.
	Purpose string `json:"purpose,omitempty"`
	// Meta carries caller values echoed back verbatim (the OIDC flow keeps its
	// client nonce and state here).
	Meta      map[string]string `json:"meta,omitempty"`
	CreatedAt time.Time         `json:"createdAt"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Used      bool              `json:"used"`
}

// Typed errors of the challenge lifecycle.
var (
	// ErrNotFound means the id is unknown (never issued, or already reaped).
	ErrNotFound = errors.New("challenge not found")
	// ErrExpired means the challenge outlived its TTL.
	ErrExpired = errors.New("challenge expired")
	// ErrUsed means the challenge was already consumed (anti-replay).
	ErrUsed = errors.New("challenge already used")
)

// Store persists issued challenges between the issue and confirm calls. Consume
// is the anti-replay seam: it atomically fetches a challenge and marks it used,
// so a second confirmation with the same id is rejected. Expiry is enforced by
// the caller (which holds the clock); Reap removes expired entries.
type Store interface {
	Create(ctx context.Context, c *Challenge) error
	// Consume atomically returns the challenge and marks it used. It returns
	// ErrNotFound if absent and ErrUsed if already consumed.
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
	if c.Meta != nil {
		cp.Meta = make(map[string]string, len(c.Meta))
		for k, v := range c.Meta {
			cp.Meta[k] = v
		}
	}
	return &cp
}

// MemStore is the ephemeral in-memory Store: fast, zero-dependency, the
// default. Challenges do not survive a restart — fine, since their TTL is short
// (minutes) and an in-flight login simply retries.
type MemStore struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
}

var _ Store = (*MemStore)(nil)

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
		return nil, ErrNotFound
	}
	if c.Used {
		return nil, ErrUsed
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

// BoltStore is the durable on-disk Store: a single bbolt file (pure Go,
// no external broker) so challenges survive a restart and can be shared across a
// single node. The file may hold client nonces, so it is created 0600.
type BoltStore struct {
	db *bolt.DB
}

var _ Store = (*BoltStore)(nil)

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
			return ErrNotFound
		}
		var c Challenge
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.Used {
			return ErrUsed
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
