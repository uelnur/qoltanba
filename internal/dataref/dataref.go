// Package dataref implements core.DataResolver: it turns a by-reference payload
// (a local path or a URL) into a local file the driver reads directly, enforcing
// the safety policy the domain must not hardcode. A local path is accepted only
// when explicitly enabled (reading arbitrary files from a request is a serious
// risk); a URL must use an allowed scheme and is streamed to a private spool file
// (0600) with a size cap and guaranteed cleanup. Error messages never echo the
// path or URL, so they cannot leak into telemetry.
package dataref

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Config tunes the resolver's safety policy.
type Config struct {
	// AllowLocalPath permits DataRef.Path (a local filesystem path). Off by
	// default — a request must not be able to make the service read any file.
	AllowLocalPath bool
	// AllowURL permits DataRef.URL (server-side fetch). Off by default — letting a
	// request drive an outbound fetch is an SSRF vector; enable it deliberately.
	AllowURL bool
	// AllowedSchemes are the URL schemes accepted for DataRef.URL (default https).
	AllowedSchemes []string
	// MaxBytes caps a resolved payload; 0 means unlimited.
	MaxBytes int64
	// SpoolDir is where fetched URLs are spooled (default os.TempDir()).
	SpoolDir string
	// Timeout bounds a URL fetch (default 30s).
	Timeout time.Duration
}

// Resolver implements core.DataResolver under a Config policy.
type Resolver struct {
	allowLocal bool
	allowURL   bool
	schemes    map[string]bool
	maxBytes   int64
	spoolDir   string
	client     *http.Client
}

var _ core.DataResolver = (*Resolver)(nil)

// New builds a Resolver from cfg, applying defaults (https-only, 30s timeout).
func New(cfg Config) *Resolver {
	schemes := map[string]bool{}
	list := cfg.AllowedSchemes
	if len(list) == 0 {
		list = []string{"https"}
	}
	for _, s := range list {
		schemes[strings.ToLower(strings.TrimSpace(s))] = true
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Resolver{
		allowLocal: cfg.AllowLocalPath,
		allowURL:   cfg.AllowURL,
		schemes:    schemes,
		maxBytes:   cfg.MaxBytes,
		spoolDir:   cfg.SpoolDir,
		client:     &http.Client{Timeout: timeout},
	}
}

// Resolve turns ref into a locally readable path.
func (r *Resolver) Resolve(ctx context.Context, ref core.DataRef) (core.ResolvedData, error) {
	switch {
	case ref.Path != "":
		return r.local(ref.Path)
	case ref.URL != "":
		return r.fetch(ctx, ref.URL)
	default:
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "empty data reference")
	}
}

// local validates and returns a caller-owned local path (no cleanup — the file is
// not ours). It is gated by the allow-local-path policy.
func (r *Resolver) local(path string) (core.ResolvedData, error) {
	if !r.allowLocal {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "local-path data is not enabled")
	}
	info, err := os.Stat(path)
	if err != nil {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "data path is not accessible")
	}
	if !info.Mode().IsRegular() {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "data path is not a regular file")
	}
	if r.maxBytes > 0 && info.Size() > r.maxBytes {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "data file exceeds the size limit")
	}
	return core.NewResolvedData(path, nil), nil
}

// fetch streams a URL to a private spool file, enforcing scheme and size policy.
func (r *Resolver) fetch(ctx context.Context, rawURL string) (core.ResolvedData, error) {
	if !r.allowURL {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "url data is not enabled")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "invalid data url")
	}
	if !r.schemes[strings.ToLower(u.Scheme)] {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "data url scheme is not allowed")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "invalid data url")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return core.ResolvedData{}, core.NewError(core.KindUnavailable, "dataref", "data url fetch failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return core.ResolvedData{}, core.NewError(core.KindUnavailable, "dataref", "data url returned a non-200 status")
	}

	f, err := os.CreateTemp(r.spoolDir, "qoltanba-data-*") // CreateTemp yields 0600
	if err != nil {
		return core.ResolvedData{}, core.NewError(core.KindInternal, "dataref", "cannot create spool file")
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }

	var src io.Reader = resp.Body
	if r.maxBytes > 0 {
		src = io.LimitReader(resp.Body, r.maxBytes+1) // +1 to detect overflow
	}
	n, cerr := io.Copy(f, src)
	closeErr := f.Close()
	if cerr != nil || closeErr != nil {
		cleanup()
		return core.ResolvedData{}, core.NewError(core.KindUnavailable, "dataref", "data url copy failed")
	}
	if r.maxBytes > 0 && n > r.maxBytes {
		cleanup()
		return core.ResolvedData{}, core.NewError(core.KindInvalid, "dataref", "data exceeds the size limit")
	}
	return core.NewResolvedData(name, cleanup), nil
}
