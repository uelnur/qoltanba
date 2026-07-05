package qr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// SessionStore persists QR sessions between create, the app's signature POST and
// the consumer's status poll. Consume is the anti-replay seam: it atomically
// fetches a session and marks it used so a second signature POST is rejected.
// Save updates a session in place (status/result transitions). Expiry is enforced
// by the caller (which holds the clock); Reap removes expired entries.
type SessionStore interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	// Consume atomically returns the session and marks it used. Returns
	// ErrSessionNotFound if absent and ErrSessionUsed if already consumed.
	Consume(ctx context.Context, id string) (*Session, error)
	Save(ctx context.Context, s *Session) error
	Reap(ctx context.Context, now time.Time) (int, error)
	Len() int
	Close() error
}

// newID returns a random 128-bit hex identifier — the unguessable capability
// token that also names the public app-facing URL.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// cloneSession deep-copies a session so stored state never aliases a caller value.
func cloneSession(s *Session) *Session {
	cp := *s
	cp.Data = append([]byte(nil), s.Data...)
	cp.Result = append(json.RawMessage(nil), s.Result...)
	if len(s.Documents) > 0 {
		cp.Documents = make([]Document, len(s.Documents))
		copy(cp.Documents, s.Documents)
	}
	if s.Error != nil {
		e := *s.Error
		cp.Error = &e
	}
	return &cp
}

// MemStore is the ephemeral in-memory SessionStore (default). Sessions do not
// survive a restart — fine, since their TTL is minutes and an in-flight sign
// simply retries.
type MemStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

var _ SessionStore = (*MemStore)(nil)

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{sessions: make(map[string]*Session)} }

func (s *MemStore) Create(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = cloneSession(sess)
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return cloneSession(sess), nil
}

func (s *MemStore) Consume(_ context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.Used {
		return nil, ErrSessionUsed
	}
	sess.Used = true
	return cloneSession(sess), nil
}

func (s *MemStore) Save(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = cloneSession(sess)
	return nil
}

func (s *MemStore) Reap(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if !sess.ExpiresAt.After(now) {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *MemStore) Close() error { return nil }

// sessionBucket holds every session keyed by id.
var sessionBucket = []byte("qr")

// BoltStore is the durable on-disk SessionStore: a single bbolt file so sessions
// survive a restart. The file may hold data-to-sign, so it is created 0600.
type BoltStore struct {
	db *bolt.DB
}

var _ SessionStore = (*BoltStore)(nil)

// OpenBoltStore opens (or creates) the bbolt database at path with 0600
// permissions and ensures the session bucket exists.
func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(sessionBucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) put(sess *Session) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(sessionBucket).Put([]byte(sess.ID), raw)
	})
}

func (s *BoltStore) Create(_ context.Context, sess *Session) error { return s.put(sess) }
func (s *BoltStore) Save(_ context.Context, sess *Session) error   { return s.put(sess) }

func (s *BoltStore) Get(_ context.Context, id string) (*Session, error) {
	var out *Session
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(sessionBucket).Get([]byte(id))
		if raw == nil {
			return ErrSessionNotFound
		}
		var sess Session
		if err := json.Unmarshal(raw, &sess); err != nil {
			return err
		}
		out = &sess
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BoltStore) Consume(_ context.Context, id string) (*Session, error) {
	var out *Session
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(sessionBucket)
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrSessionNotFound
		}
		var sess Session
		if err := json.Unmarshal(raw, &sess); err != nil {
			return err
		}
		if sess.Used {
			return ErrSessionUsed
		}
		sess.Used = true
		updated, err := json.Marshal(&sess)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(id), updated); err != nil {
			return err
		}
		out = &sess
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
		b := tx.Bucket(sessionBucket)
		if err := b.ForEach(func(k, raw []byte) error {
			var sess Session
			if err := json.Unmarshal(raw, &sess); err != nil {
				return err
			}
			if !sess.ExpiresAt.After(now) {
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
		n = tx.Bucket(sessionBucket).Stats().KeyN
		return nil
	})
	return n
}

func (s *BoltStore) Close() error { return s.db.Close() }
