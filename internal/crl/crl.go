// Package crl implements the core.CRLSource port: it supplies a certificate's CRL
// (Certificate Revocation List) for revocation checking. It fetches CRLs from the
// certificate's distribution points over HTTP and caches them, then reports enough
// about base↔delta consistency and freshness for the domain to apply a fail
// policy. It is infrastructure behind a domain-declared interface — the domain
// decides when a CRL check runs and what to do when a CRL is unreliable; this
// package only fetches, caches and consistency-checks.
//
// Storage. With an empty spool directory the cache keeps CRL bodies in memory.
// With a spool directory the bodies live on disk (keyed by a hash of the
// distribution-point URL), metadata stays in memory, and the cache survives a
// restart: New scans the directory and re-adopts still-parsable files (warm
// start). Total on-disk size is bounded; the least-recently-used entries are
// evicted first. NUC CRLs are large, so keeping them off the heap matters.
//
// Freshness. Each cached CRL carries its nextUpdate; a lookup past nextUpdate
// re-downloads. A refetch failure falls back to the last cached copy (stale but
// available) — reported as not-fresh so the domain can decide, rather than a
// silent miss.
//
// Delta. When a certificate has a Freshest-CRL (delta) distribution point, the
// cache fetches the delta too and checks it against the base: the delta's
// BaseCRLNumber must not exceed the base CRLNumber and the authority key
// identifiers must match. A consistent, fresh delta is returned alongside the base
// for the domain to overlay; an inconsistent, stale or unavailable delta marks the
// result unreliable (the domain then applies its CRL fail policy — typically
// falling back to OCSP, which is authoritative for real-time status).
package crl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/uelnur/qoltanba/internal/core"
)

// maxCRLBytes caps a single CRL download. NUC CRLs are large but bounded.
const maxCRLBytes = 16 << 20 // 16 MiB

// defaultMaxBytes bounds total spooled CRL bytes when the config gives no cap.
const defaultMaxBytes = 256 << 20 // 256 MiB

var (
	// oidFreshestCRL (2.5.29.46) points at the delta CRL from a certificate.
	oidFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}
	// oidDeltaCRLIndicator (2.5.29.27) carries a delta CRL's BaseCRLNumber.
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
)

var errNoBody = errors.New("crl: cache entry has no body")

// entry is a cached CRL's metadata. The body is either resident (der) or spooled
// (path); exactly one is set.
type entry struct {
	der        []byte    // resident body (in-memory mode); nil when spooled
	path       string    // spool file (disk mode); "" when in-memory
	size       int64     // body size, for the spool size cap
	nextUpdate time.Time // zero means "no nextUpdate" → always refetch on next lookup
	number     *big.Int  // this CRL's CRLNumber (nil if absent); base for delta comparison
	baseNumber *big.Int  // a delta CRL's BaseCRLNumber (nil for a base CRL)
	aki        []byte    // authority key identifier, for issuer matching across base/delta
	lastUsed   time.Time // for LRU eviction
}

// Config configures a Cache.
type Config struct {
	// Timeout is the per-request HTTP timeout (<=0 uses 10s).
	Timeout time.Duration
	// SpoolDir, when non-empty, stores CRL bodies on disk (persistent, warm-started
	// on New). Empty keeps bodies in memory.
	SpoolDir string
	// MaxBytes caps total cached CRL bytes (<=0 uses 256 MiB). LRU eviction applies.
	MaxBytes int64
}

// Cache fetches and caches CRLs by distribution-point URL and resolves base↔delta
// consistency for a certificate.
type Cache struct {
	client   *http.Client
	now      func() time.Time
	fetch    fetchFunc
	spoolDir string
	maxBytes int64

	mu      sync.Mutex
	entries map[string]entry
	total   int64

	hits   atomic.Uint64 // served from a fresh cached entry
	misses atomic.Uint64 // required a network fetch (or fell back to stale)
}

// fetchFunc downloads raw bytes at a URL, reporting false on any failure. It is
// injectable so the cache can be tested without network access.
type fetchFunc func(ctx context.Context, url string) ([]byte, bool)

// New builds a Cache from cfg. In spool mode it creates the directory and warm-
// starts from any CRLs already there.
func New(cfg Config) *Cache {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	c := &Cache{
		client:   &http.Client{Timeout: timeout},
		now:      time.Now,
		spoolDir: cfg.SpoolDir,
		maxBytes: maxBytes,
		entries:  map[string]entry{},
	}
	c.fetch = c.httpFetch
	if c.spoolDir != "" {
		if err := os.MkdirAll(c.spoolDir, 0o700); err == nil {
			c.warmStart()
		} else {
			c.spoolDir = "" // cannot spool → degrade to in-memory
		}
	}
	return c
}

// Stats reports cumulative cache hits (served fresh) and misses (fetched or
// stale-fallback) for metrics.
func (c *Cache) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// CRLFor implements core.CRLSource: it resolves the base CRL (and any consistent
// delta) for a certificate. ok is false when the certificate has no CRL
// distribution point or none could be fetched; otherwise the result's Reliable
// flag and Reason report whether the CRL is fresh and base↔delta consistent.
func (c *Cache) CRLFor(ctx context.Context, certDER []byte) (core.CRLResult, bool) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return core.CRLResult{}, false
	}

	base, baseMeta, baseFresh, found := c.first(ctx, cert.CRLDistributionPoints)
	if !found {
		return core.CRLResult{}, false
	}

	res := core.CRLResult{Base: base, Reliable: true}
	if !baseFresh {
		res.Reliable = false
		res.Reason = "stale-base"
	}

	deltaURLs := freshestCRLURLs(cert)
	if len(deltaURLs) == 0 {
		return res, true
	}

	setReason := func(r string) {
		res.Reliable = false
		if res.Reason == "" {
			res.Reason = r
		}
	}
	delta, deltaMeta, deltaFresh, deltaFound := c.first(ctx, deltaURLs)
	switch {
	case !deltaFound:
		setReason("delta-unavailable")
	case !deltaFresh:
		setReason("stale-delta")
	case consistent(baseMeta, deltaMeta):
		res.Delta = delta // fresh and consistent → domain may overlay its revocations
	default:
		setReason("delta-inconsistent")
	}
	return res, true
}

// first returns the first URL that yields a CRL, with its metadata and freshness.
func (c *Cache) first(ctx context.Context, urls []string) (der []byte, meta entry, fresh, ok bool) {
	for _, url := range urls {
		if der, meta, fresh, ok = c.get(ctx, url); ok {
			return der, meta, fresh, true
		}
	}
	return nil, entry{}, false, false
}

// get returns the CRL DER for a URL with its metadata, refetching when the cached
// copy is past its nextUpdate. On a refetch failure it falls back to the stale
// cached copy (reported fresh=false). ok is false only when nothing is available.
func (c *Cache) get(ctx context.Context, url string) (der []byte, meta entry, fresh, ok bool) {
	key := keyFor(url)

	c.mu.Lock()
	cached, seen := c.entries[key]
	if seen {
		cached.lastUsed = c.now()
		c.entries[key] = cached
	}
	c.mu.Unlock()

	if seen && !cached.nextUpdate.IsZero() && c.now().Before(cached.nextUpdate) {
		if body, err := c.body(cached); err == nil {
			c.hits.Add(1)
			return body, cached, true, true
		}
		// Spooled body vanished (evicted/removed) → fall through and refetch.
	}
	c.misses.Add(1)

	body, fetched := c.fetch(ctx, url)
	if !fetched {
		return c.staleFallback(cached, seen)
	}
	normalized := normalizeCRL(body)
	if normalized == nil {
		return c.staleFallback(cached, seen)
	}
	stored := c.store(key, normalized)
	return normalized, stored, true, true
}

// staleFallback returns the last cached body when a refetch fails, or a miss.
func (c *Cache) staleFallback(cached entry, seen bool) (der []byte, meta entry, fresh, ok bool) {
	if seen {
		if body, err := c.body(cached); err == nil {
			return body, cached, false, true // stale-but-available
		}
	}
	return nil, entry{}, false, false
}

// store persists a freshly fetched CRL (to disk in spool mode, else in memory),
// records its metadata, and evicts LRU entries if the size cap is exceeded.
func (c *Cache) store(key string, der []byte) entry {
	e := entry{size: int64(len(der)), lastUsed: c.now()}
	e.nextUpdate, e.number, e.baseNumber, e.aki = parseMeta(der)

	if c.spoolDir != "" {
		path := filepath.Join(c.spoolDir, key+".crl")
		if err := writeFileAtomic(path, der); err == nil {
			e.path = path
		} else {
			e.der = der // spool write failed → keep it resident
		}
	} else {
		e.der = der
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[key]; ok {
		c.total -= old.size
		if old.path != "" && old.path != e.path {
			_ = os.Remove(old.path)
		}
	}
	c.entries[key] = e
	c.total += e.size
	c.evictLocked(key)
	return e
}

// evictLocked drops least-recently-used entries until total size is within the
// cap. keep is never evicted (it is the entry just stored). Caller holds mu.
func (c *Cache) evictLocked(keep string) {
	for c.total > c.maxBytes && len(c.entries) > 1 {
		var victim string
		var oldest time.Time
		first := true
		for k, e := range c.entries {
			if k == keep {
				continue
			}
			if first || e.lastUsed.Before(oldest) {
				victim, oldest, first = k, e.lastUsed, false
			}
		}
		if first {
			return // nothing but keep remains
		}
		e := c.entries[victim]
		if e.path != "" {
			_ = os.Remove(e.path)
		}
		c.total -= e.size
		delete(c.entries, victim)
	}
}

// body returns an entry's CRL bytes, reading from disk in spool mode.
func (c *Cache) body(e entry) ([]byte, error) {
	if e.der != nil {
		return e.der, nil
	}
	if e.path != "" {
		return os.ReadFile(e.path)
	}
	return nil, errNoBody
}

// warmStart adopts still-parsable CRL files already in the spool directory so a
// restart keeps a warm cache. Unparsable files are removed.
func (c *Cache) warmStart() {
	ents, err := os.ReadDir(c.spoolDir)
	if err != nil {
		return
	}
	for _, de := range ents {
		if de.IsDir() || filepath.Ext(de.Name()) != ".crl" {
			continue
		}
		path := filepath.Join(c.spoolDir, de.Name())
		der, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if normalizeCRL(der) == nil {
			_ = os.Remove(path)
			continue
		}
		key := strings.TrimSuffix(de.Name(), ".crl")
		e := entry{path: path, size: int64(len(der)), lastUsed: c.now()}
		e.nextUpdate, e.number, e.baseNumber, e.aki = parseMeta(der)
		c.entries[key] = e
		c.total += e.size
	}
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

// consistent reports whether a delta CRL is coherent with the base CRL we hold:
// the delta's BaseCRLNumber must not exceed our base CRLNumber (else the delta
// needs a base newer than we have), and the authority key identifiers must match
// when both are present (same issuer).
func consistent(base, delta entry) bool {
	if delta.baseNumber == nil || base.number == nil {
		return false // not a proper delta, or an unknown base number → cannot trust it
	}
	if delta.baseNumber.Cmp(base.number) > 0 {
		return false
	}
	if len(base.aki) > 0 && len(delta.aki) > 0 && !bytes.Equal(base.aki, delta.aki) {
		return false
	}
	return true
}

// parseMeta extracts the freshness and delta-consistency fields from a CRL. The
// bytes are expected to already parse (normalizeCRL validated them); on any
// failure the zero values are returned.
func parseMeta(der []byte) (nextUpdate time.Time, number, baseNumber *big.Int, aki []byte) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return time.Time{}, nil, nil, nil
	}
	nextUpdate = rl.NextUpdate
	number = rl.Number
	aki = rl.AuthorityKeyId
	for _, ext := range rl.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) {
			// asn1 handles *big.Int as the target, so unmarshal into **big.Int.
			var n *big.Int
			if _, e := asn1.Unmarshal(ext.Value, &n); e == nil {
				baseNumber = n
			}
		}
	}
	return nextUpdate, number, baseNumber, aki
}

// freshestCRLURLs returns the delta-CRL distribution URLs from a certificate's
// Freshest-CRL extension (structurally identical to CRLDistributionPoints).
func freshestCRLURLs(cert *x509.Certificate) []string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFreshestCRL) {
			return parseDistributionPointURIs(ext.Value)
		}
	}
	return nil
}

// parseDistributionPointURIs pulls the fullName URIs out of a
// CRLDistributionPoints/FreshestCRL DER value. It mirrors the parse crypto/x509
// applies to the base CRLDistributionPoints extension.
func parseDistributionPointURIs(der []byte) []string {
	var urls []string
	val := cryptobyte.String(der)
	if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return nil
	}
	for !val.Empty() {
		var dp cryptobyte.String
		if !val.ReadASN1(&dp, cryptobyte_asn1.SEQUENCE) {
			return urls
		}
		var name cryptobyte.String
		var present bool
		if !dp.ReadOptionalASN1(&name, &present, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return urls
		}
		if !present {
			continue
		}
		if !name.ReadASN1(&name, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			continue
		}
		for !name.Empty() {
			if !name.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
				break
			}
			var uri cryptobyte.String
			if !name.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return urls
			}
			urls = append(urls, string(uri))
		}
	}
	return urls
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

// keyFor maps a distribution-point URL to a filesystem-safe cache key.
func keyFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic writes data to path via a temp file and rename, so a concurrent
// reader never sees a partial CRL.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".crl-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
