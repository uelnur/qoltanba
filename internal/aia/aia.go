// Package aia implements the core.IssuerFetcher port: it downloads a
// certificate's issuer via the Authority Information Access "CA Issuers" URL.
// It is infrastructure behind a domain-declared interface; the domain decides
// when to walk the chain, this package only fetches.
//
// Robustness: a bounded HTTP client (timeout, response-size cap), an in-memory
// URL cache, and content sniffing for DER or PEM certificates. PKCS#7 (.p7c)
// bundles are not decoded here (no stdlib support) — such endpoints simply miss.
// The domain re-checks that a fetched certificate is really the issuer (subject
// match + signature where verifiable), so a wrong download cannot poison a chain.
package aia

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"sync"
	"time"
)

// maxResponseBytes caps a single AIA download.
const maxResponseBytes = 2 << 20 // 2 MiB

// Fetcher downloads issuer certificates over HTTP with a cache.
type Fetcher struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string][]byte // URL → issuer DER (nil entry = known miss)
}

// New builds a Fetcher with the given per-request timeout (<=0 uses 5s).
func New(timeout time.Duration) *Fetcher {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Fetcher{
		client: &http.Client{Timeout: timeout},
		cache:  map[string][]byte{},
	}
}

// FetchIssuer implements core.IssuerFetcher: it parses certDER, tries each CA
// Issuers URL, and returns the first downloaded certificate as DER.
func (f *Fetcher) FetchIssuer(ctx context.Context, certDER []byte) ([]byte, bool) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, false
	}
	for _, url := range c.IssuingCertificateURL {
		if der, ok := f.get(ctx, url); ok {
			return der, true
		}
	}
	return nil, false
}

// get returns the issuer DER for a URL, using the cache.
func (f *Fetcher) get(ctx context.Context, url string) ([]byte, bool) {
	f.mu.Lock()
	if der, seen := f.cache[url]; seen {
		f.mu.Unlock()
		return der, der != nil
	}
	f.mu.Unlock()

	der := f.download(ctx, url)
	f.mu.Lock()
	f.cache[url] = der // cache misses too, to avoid re-hitting a dead URL
	f.mu.Unlock()
	return der, der != nil
}

// download fetches url and extracts a certificate as DER (nil on any failure).
func (f *Fetcher) download(ctx context.Context, url string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil
	}
	return extractCert(body)
}

// extractCert pulls the first certificate out of PEM, DER or PKCS#7 (.p7c) bytes.
func extractCert(body []byte) []byte {
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		return block.Bytes
	}
	if certs, err := x509.ParseCertificates(body); err == nil && len(certs) > 0 {
		return certs[0].Raw
	}
	if certs := parsePKCS7Certs(body); len(certs) > 0 {
		return certs[0].Raw
	}
	return nil
}
