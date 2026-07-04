package trust

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/uelnur/qoltanba/internal/pki"
)

// maxCertBytes caps a single CA download.
const maxCertBytes = 1 << 20 // 1 MiB

// FetchFunc downloads the bytes at a URL. It returns false on any failure. It is
// injectable so registry loading can be tested without network access.
type FetchFunc func(ctx context.Context, url string) ([]byte, bool)

// LoadRegistry fetches the given RK CA references (from internal/pki) and adds
// the certificates as anchors. It is best-effort: each failed reference is
// collected as an error and returned, without aborting the rest — a partial
// trust store still works. Source 3 in validation.md (the official CA registry).
func (s *Store) LoadRegistry(ctx context.Context, refs []pki.CACertRef, fetch FetchFunc) []error {
	var errs []error
	for _, ref := range refs {
		body, ok := fetch(ctx, ref.URL)
		if !ok {
			errs = append(errs, fmt.Errorf("trust: fetch %s (%s): failed", ref.Label, ref.URL))
			continue
		}
		if der := certDER(body); der == nil || !s.addDER(der) {
			errs = append(errs, fmt.Errorf("trust: parse %s (%s): not a certificate", ref.Label, ref.URL))
		}
	}
	return errs
}

// HTTPFetcher returns a FetchFunc backed by a bounded HTTP client.
func HTTPFetcher(timeout time.Duration) FetchFunc {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, url string) ([]byte, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, false
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, false
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBytes))
		if err != nil {
			return nil, false
		}
		return body, true
	}
}

// certDER normalizes a fetched CA certificate to DER (PEM is decoded; raw DER is
// passed through). Returns nil when the bytes are neither.
func certDER(body []byte) []byte {
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		return block.Bytes
	}
	return body // assume DER; addDER validates by parsing
}
