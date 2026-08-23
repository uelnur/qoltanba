package multisign

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// cloneSession deep-copies a session so stored state never aliases a caller's
// value (and vice versa).
func cloneSession(s *Session) *Session {
	cp := *s
	cp.Document = append([]byte(nil), s.Document...)
	cp.Container = append([]byte(nil), s.Container...)
	cp.Required = append([]Required(nil), s.Required...)
	cp.Collected = append([]Signature(nil), s.Collected...)
	return &cp
}

// MemStore is the ephemeral in-memory Store. Fine for a demo or a single short flow;
// a real document round outlives a restart, so production wants the bolt store.
type MemStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

var _ Store = (*MemStore)(nil)

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
		return nil, ErrNotFound
	}
	return cloneSession(sess), nil
}

func (s *MemStore) Save(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sess.ID]; !ok {
		return ErrNotFound
	}
	s.sessions[sess.ID] = cloneSession(sess)
	return nil
}

func (s *MemStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *MemStore) Close() error { return nil }

// sessionBucket holds every session keyed by id.
var sessionBucket = []byte("multisign")

// BoltStore is the durable on-disk Store: a single bbolt file (pure Go, no
// external broker) so a signing round survives a restart or a deploy. The file
// holds document content, so it is created 0600.
type BoltStore struct {
	db *bolt.DB
}

var _ Store = (*BoltStore)(nil)

// OpenBoltStore opens (or creates) the database at path.
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

func (s *BoltStore) Create(_ context.Context, sess *Session) error { return s.put(sess) }

func (s *BoltStore) Save(ctx context.Context, sess *Session) error {
	// Save is an update of something that must already exist: silently creating it
	// would hide a lost session behind a fresh, empty one.
	if _, err := s.Get(ctx, sess.ID); err != nil {
		return err
	}
	return s.put(sess)
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

func (s *BoltStore) Get(_ context.Context, id string) (*Session, error) {
	var out *Session
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(sessionBucket).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
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

func (s *BoltStore) Delete(_ context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(sessionBucket).Delete([]byte(id))
	})
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
