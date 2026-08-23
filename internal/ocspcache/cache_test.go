package ocspcache

import (
	"testing"
	"time"
)

func at(t time.Time) *time.Time { return &t }

func TestLookupHitAndMiss(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := New(Config{Now: func() time.Time { return now }})
	cert := []byte("cert-der")

	if _, ok := c.Lookup(cert, "http://ocsp"); ok {
		t.Fatal("empty cache reported a hit")
	}
	c.Store(cert, "http://ocsp", Entry{Response: []byte("resp"), NextUpdate: at(now.Add(time.Hour))})

	got, ok := c.Lookup(cert, "http://ocsp")
	if !ok || string(got.Response) != "resp" {
		t.Fatalf("lookup = %+v, %v", got, ok)
	}
	if hits, misses := c.Stats(); hits != 1 || misses != 1 {
		t.Errorf("stats = %d hits, %d misses, want 1/1", hits, misses)
	}
}

// TestResponderIsPartOfTheKey keeps a test-PKI answer from being served for a
// production check of the same certificate.
func TestResponderIsPartOfTheKey(t *testing.T) {
	now := time.Now()
	c := New(Config{Now: func() time.Time { return now }})
	cert := []byte("cert-der")
	c.Store(cert, "http://test.pki.gov.kz/ocsp/", Entry{NextUpdate: at(now.Add(time.Hour))})

	if _, ok := c.Lookup(cert, "http://ocsp.pki.gov.kz"); ok {
		t.Error("an answer from one responder was served for another")
	}
}

// TestExpiryFollowsResponder pins the freshness rule: an entry never outlives the
// nextUpdate the responder promised.
func TestExpiryFollowsResponder(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := now
	c := New(Config{TTL: time.Hour, Now: func() time.Time { return clock }})
	cert := []byte("cert")
	c.Store(cert, "r", Entry{NextUpdate: at(now.Add(2 * time.Minute))})

	clock = now.Add(time.Minute)
	if _, ok := c.Lookup(cert, "r"); !ok {
		t.Fatal("entry expired before its nextUpdate")
	}
	clock = now.Add(3 * time.Minute)
	if _, ok := c.Lookup(cert, "r"); ok {
		t.Error("entry outlived its nextUpdate")
	}
}

func TestTTLBoundsAnswerWithoutNextUpdate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := now
	c := New(Config{TTL: time.Minute, Now: func() time.Time { return clock }})
	c.Store([]byte("cert"), "r", Entry{}) // no nextUpdate: no freshness promise

	clock = now.Add(90 * time.Second)
	if _, ok := c.Lookup([]byte("cert"), "r"); ok {
		t.Error("an answer without nextUpdate outlived the configured TTL")
	}
}

// TestRevokedIsCachedLonger covers the monotonicity of revocation: the verdict
// cannot flip back, so it is kept well past a "good" answer's lifetime.
func TestRevokedIsCachedLonger(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := now
	c := New(Config{TTL: time.Minute, RevokedTTL: time.Hour, Now: func() time.Time { return clock }})
	c.Store([]byte("cert"), "r", Entry{Revoked: true, Reason: "superseded"})

	clock = now.Add(30 * time.Minute)
	got, ok := c.Lookup([]byte("cert"), "r")
	if !ok || !got.Revoked || got.Reason != "superseded" {
		t.Fatalf("revoked verdict lost after %v: %+v, %v", 30*time.Minute, got, ok)
	}
}

func TestStaleOnArrivalIsNotStored(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := New(Config{Now: func() time.Time { return now }})
	c.Store([]byte("cert"), "r", Entry{NextUpdate: at(now.Add(-time.Minute))})

	if c.Len() != 0 {
		t.Error("an already-stale answer was cached")
	}
}

func TestEvictionBoundsTheCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := New(Config{MaxEntries: 3, Now: func() time.Time { return now }})
	for i := 0; i < 10; i++ {
		c.Store([]byte{byte(i)}, "r", Entry{NextUpdate: at(now.Add(time.Hour))})
	}
	if got := c.Len(); got > 3 {
		t.Errorf("cache holds %d entries, want at most 3", got)
	}
	// The newest survives; the oldest went first.
	if _, ok := c.Lookup([]byte{9}, "r"); !ok {
		t.Error("the newest entry was evicted")
	}
	if _, ok := c.Lookup([]byte{0}, "r"); ok {
		t.Error("the oldest entry survived eviction")
	}
}
