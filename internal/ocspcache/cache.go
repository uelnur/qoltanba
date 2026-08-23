// Package ocspcache caches OCSP revocation answers so repeated checks of the same
// certificate do not each hit the responder.
//
// The library performs the OCSP request itself, so this caches the *answer*, not
// the HTTP exchange: a hit skips the native call entirely. That is what makes it
// both a load reducer for pki.gov.kz and a stapling source — the raw response is
// kept alongside the verdict, so a caller asking for it gets the same bytes the
// responder produced.
//
// Freshness follows the responder: an entry lives until the answer's nextUpdate,
// or a configured TTL when the answer carries none. A "revoked" verdict is kept
// far longer, because revocation is monotonic — a certificate that was revoked
// does not become valid again — which also keeps a revoked certificate from
// slipping through while the responder is unreachable.
package ocspcache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for an unset Config field.
const (
	defaultTTL        = 10 * time.Minute
	defaultRevokedTTL = 24 * time.Hour
	defaultMaxEntries = 4096
)

// Config parameterizes a Cache.
type Config struct {
	// TTL bounds a "good" answer that carries no nextUpdate. Zero uses 10m — short,
	// because without nextUpdate the responder gave no freshness promise.
	TTL time.Duration
	// RevokedTTL bounds a "revoked" answer. Zero uses 24h: the verdict cannot flip
	// back, so caching it long is safe and keeps a revoked certificate from being
	// re-checked (and possibly missed) on every call.
	RevokedTTL time.Duration
	// MaxEntries bounds the cache. Zero uses 4096.
	MaxEntries int
	// Now injects the clock (tests).
	Now func() time.Time
}

// Entry is one cached answer: the verdict fields the domain fills plus the raw
// response for stapling.
type Entry struct {
	Revoked        bool
	Reason         string
	RevocationTime *time.Time
	ThisUpdate     *time.Time
	NextUpdate     *time.Time
	ProducedAt     *time.Time
	Response       []byte
}

type entry struct {
	value   Entry
	expires time.Time
	// seq orders entries for eviction: the oldest insertion goes first. A strict
	// LRU would need a list per read; insertion order is enough for a cache whose
	// entries expire on their own anyway.
	seq uint64
}

// Cache is a bounded in-memory OCSP answer cache, safe for concurrent use.
type Cache struct {
	cfg Config

	mu      sync.Mutex
	entries map[string]*entry
	seq     uint64

	hits, misses, stapled atomic.Uint64
}

// New builds a cache.
func New(cfg Config) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.RevokedTTL <= 0 {
		cfg.RevokedTTL = defaultRevokedTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cache{cfg: cfg, entries: make(map[string]*entry)}
}

// Lookup returns a live answer for the certificate checked against responder.
func (c *Cache) Lookup(certDER []byte, responder string) (Entry, bool) {
	k := key(certDER, responder)
	now := c.cfg.Now()

	c.mu.Lock()
	e, ok := c.entries[k]
	if ok && !e.expires.After(now) {
		delete(c.entries, k)
		ok = false
	}
	c.mu.Unlock()

	if !ok {
		c.misses.Add(1)
		return Entry{}, false
	}
	c.hits.Add(1)
	if len(e.value.Response) > 0 {
		c.stapled.Add(1)
	}
	return e.value, true
}

// Store records an answer. Its lifetime comes from the responder's nextUpdate,
// bounded by the configured TTL so a responder promising a week does not pin a
// stale answer for a week.
func (c *Cache) Store(certDER []byte, responder string, v Entry) {
	now := c.cfg.Now()
	ttl := c.cfg.TTL
	if v.Revoked {
		ttl = c.cfg.RevokedTTL
	}
	expires := now.Add(ttl)
	if v.NextUpdate != nil && v.NextUpdate.Before(expires) {
		// Never outlive what the responder promised.
		expires = *v.NextUpdate
	}
	if !expires.After(now) {
		return // already stale on arrival: caching it would only serve staleness
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	c.entries[key(certDER, responder)] = &entry{value: v, expires: expires, seq: c.seq}
	c.evictLocked(now)
}

// evictLocked drops expired entries first and, if still over the bound, the
// oldest ones.
func (c *Cache) evictLocked(now time.Time) {
	if len(c.entries) <= c.cfg.MaxEntries {
		return
	}
	for k, e := range c.entries {
		if !e.expires.After(now) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) > c.cfg.MaxEntries {
		var oldestKey string
		var oldestSeq uint64
		for k, e := range c.entries {
			if oldestKey == "" || e.seq < oldestSeq {
				oldestKey, oldestSeq = k, e.seq
			}
		}
		delete(c.entries, oldestKey)
	}
}

// Stats returns cumulative hits and misses, for the metrics collector.
func (c *Cache) Stats() (hits, misses uint64) { return c.hits.Load(), c.misses.Load() }

// Len reports the number of entries currently held.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// key identifies a cached answer. The responder is part of it because the same
// certificate checked against a different responder is a different answer (test
// versus production PKI, or a proxy).
func key(certDER []byte, responder string) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:]) + "\x00" + responder
}
