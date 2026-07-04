// Package crl implements the core.CRLSource port: it supplies a certificate's CRL
// (Certificate Revocation List) for revocation checking, fetched from the cert's
// CRL Distribution Points over HTTP and cached in memory. It is infrastructure
// behind a domain-declared interface — the domain decides when a CRL check runs;
// this package only fetches and caches.
//
// Freshness: each cached CRL carries its nextUpdate; a lookup past nextUpdate
// re-downloads. A refetch failure falls back to the last cached copy (stale but
// available) rather than a miss, so a transient network fault does not break
// validation — Kalkan still applies its own time checks to the CRL.
package crl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// maxCRLBytes caps a single CRL download. NUC CRLs are large but bounded.
const maxCRLBytes = 16 << 20 // 16 MiB

type entry struct {
	der        []byte
	nextUpdate time.Time // zero means "no nextUpdate" → always refetch on next lookup
}

// Cache fetches and caches CRLs by distribution-point URL.
type Cache struct {
	client *http.Client
	now    func() time.Time
	fetch  fetchFunc

	mu      sync.Mutex
	entries map[string]entry

	hits   atomic.Uint64 // served from a fresh cached entry
	misses atomic.Uint64 // required a network fetch (or fell back to stale)
}

// fetchFunc downloads raw bytes at a URL, reporting false on any failure. It is
// injectable so the cache can be tested without network access.
type fetchFunc func(ctx context.Context, url string) ([]byte, bool)

// New builds a Cache with the given per-request timeout (<=0 uses 10s).
func New(timeout time.Duration) *Cache {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	c := &Cache{
		client:  client,
		now:     time.Now,
		entries: map[string]entry{},
	}
	c.fetch = c.httpFetch
	return c
}

// Stats reports cumulative cache hits (served fresh) and misses (fetched or
// stale-fallback) for metrics.
func (c *Cache) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// CRLFor implements core.CRLSource: it parses certDER, tries each CRL
// distribution point, and returns the first CRL as DER. ok=false when the
// certificate has no CRL DP or none could be fetched.
func (c *Cache) CRLFor(ctx context.Context, certDER []byte) ([]byte, bool) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, false
	}
	for _, url := range cert.CRLDistributionPoints {
		if der, ok := c.get(ctx, url); ok {
			return der, true
		}
	}
	return nil, false
}

// get returns the CRL DER for a URL, refetching when the cached copy is past its
// nextUpdate. On a refetch failure it falls back to the stale cached copy.
func (c *Cache) get(ctx context.Context, url string) ([]byte, bool) {
	c.mu.Lock()
	cached, seen := c.entries[url]
	c.mu.Unlock()

	fresh := seen && !cached.nextUpdate.IsZero() && c.now().Before(cached.nextUpdate)
	if fresh {
		c.hits.Add(1)
		return cached.der, true
	}
	c.misses.Add(1)

	body, ok := c.fetch(ctx, url)
	if !ok {
		if seen {
			return cached.der, true // stale-but-available fallback
		}
		return nil, false
	}
	der := normalizeCRL(body)
	if der == nil {
		if seen {
			return cached.der, true
		}
		return nil, false
	}
	e := entry{der: der}
	if rl, err := x509.ParseRevocationList(der); err == nil {
		e.nextUpdate = rl.NextUpdate
	}
	c.mu.Lock()
	c.entries[url] = e
	c.mu.Unlock()
	return der, true
}

// httpFetch is the production fetchFunc: a bounded GET.
func (c *Cache) httpFetch(ctx context.Context, url string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes))
	if err != nil {
		return nil, false
	}
	return body, true
}

// normalizeCRL returns the CRL as DER (PEM is decoded; raw DER passes through).
// Returns nil when the bytes do not parse as a revocation list.
func normalizeCRL(body []byte) []byte {
	der := body
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	}
	if _, err := x509.ParseRevocationList(der); err != nil {
		return nil
	}
	return der
}
