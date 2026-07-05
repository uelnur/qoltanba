package oidc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testChallenge(id string, exp time.Time) *Challenge {
	return &Challenge{ID: id, Nonce: []byte("nonce-" + id), ExpiresAt: exp}
}

// storeContract exercises the behavior every ChallengeStore must share.
func storeContract(t *testing.T, newStore func() ChallengeStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	t.Run("consume once then replay rejected", func(t *testing.T) {
		s := newStore()
		defer s.Close()
		if err := s.Create(ctx, testChallenge("a", now.Add(time.Minute))); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Consume(ctx, "a")
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if string(got.Nonce) != "nonce-a" {
			t.Errorf("nonce = %q", got.Nonce)
		}
		if _, err := s.Consume(ctx, "a"); !errors.Is(err, ErrChallengeUsed) {
			t.Fatalf("replay err = %v, want ErrChallengeUsed", err)
		}
	})

	t.Run("unknown id", func(t *testing.T) {
		s := newStore()
		defer s.Close()
		if _, err := s.Consume(ctx, "missing"); !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("err = %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("reap removes expired", func(t *testing.T) {
		s := newStore()
		defer s.Close()
		_ = s.Create(ctx, testChallenge("old", now.Add(-time.Minute)))
		_ = s.Create(ctx, testChallenge("fresh", now.Add(time.Minute)))
		n, err := s.Reap(ctx, now)
		if err != nil {
			t.Fatalf("Reap: %v", err)
		}
		if n != 1 {
			t.Errorf("reaped = %d, want 1", n)
		}
		if s.Len() != 1 {
			t.Errorf("len = %d, want 1", s.Len())
		}
		if _, err := s.Consume(ctx, "old"); !errors.Is(err, ErrChallengeNotFound) {
			t.Errorf("expired still present: %v", err)
		}
	})
}

func TestMemStore(t *testing.T) {
	storeContract(t, func() ChallengeStore { return NewMemStore() })
}

func TestBoltStore(t *testing.T) {
	storeContract(t, func() ChallengeStore {
		s, err := OpenBoltStore(filepath.Join(t.TempDir(), "oidc.db"))
		if err != nil {
			t.Fatalf("OpenBoltStore: %v", err)
		}
		return s
	})
}
