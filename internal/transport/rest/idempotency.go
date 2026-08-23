package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/uelnur/qoltanba/internal/idempotency"
)

// Idempotency support: a caller sets an `Idempotency-Key` header on a mutating
// request; a repeat with the same key replays the first response instead of
// re-executing — so a network retry or a double-click does not produce a second
// signature. Only successful (2xx) responses are cached; a non-2xx or transient
// outcome is re-run on retry. The key is namespaced by method+path so the same
// key on different endpoints never collides. No header (or no configured cache)
// is a transparent passthrough.

// WithIdempotency enables Idempotency-Key handling on the mutating endpoints,
// backed by the given cache. Nil (the default) disables it.
func WithIdempotency(c *idempotency.Cache) Option { return func(s *Server) { s.idem = c } }

// cachedResponse is the stored form of a replayable response: status, content
// type and body. Headers beyond content type are not replayed (responses are
// self-contained JSON).
type cachedResponse struct {
	Status      int    `json:"s"`
	ContentType string `json:"ct,omitempty"`
	Body        []byte `json:"b,omitempty"`
}

// idempotent wraps a mutating handler so a repeated Idempotency-Key replays the
// first successful response. It is a no-op passthrough when idempotency is off or
// the header is absent.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if s.idem == nil || key == "" {
			next(w, r)
			return
		}
		cacheKey := r.Method + "\x00" + r.URL.Path + "\x00" + key
		data, replayed, err := s.idem.Do(r.Context(), cacheKey, func() ([]byte, error) {
			rec := &responseRecorder{status: http.StatusOK, header: make(http.Header)}
			next(rec, r)
			if rec.status < 200 || rec.status >= 300 {
				// Do not cache non-2xx: let a retry re-execute (errNotCached signals
				// "ran but not cacheable" so the runner still returns this response).
				return nil, &nonCacheable{rec: rec}
			}
			blob, merr := json.Marshal(cachedResponse{
				Status: rec.status, ContentType: rec.header.Get("Content-Type"), Body: rec.body.Bytes(),
			})
			return blob, merr
		})
		if err != nil {
			// A non-2xx runner carries its own response; anything else (context,
			// coalesced transient) re-runs to produce a fresh response.
			var nc *nonCacheable
			if errors.As(err, &nc) {
				nc.rec.flushTo(w)
				return
			}
			next(w, r)
			return
		}
		var cr cachedResponse
		if json.Unmarshal(data, &cr) != nil {
			next(w, r) // corrupt cache entry: fail open
			return
		}
		if replayed {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		if cr.ContentType != "" {
			w.Header().Set("Content-Type", cr.ContentType)
		}
		w.WriteHeader(cr.Status)
		_, _ = w.Write(cr.Body)
	}
}

// nonCacheable wraps the recorded response of a run whose status must not be
// cached, so the runner can still deliver it. It implements error to travel
// through the cache's fn error return.
type nonCacheable struct{ rec *responseRecorder }

func (n *nonCacheable) Error() string { return "idempotency: non-2xx response not cached" }

// responseRecorder captures a handler's response for caching/replay.
type responseRecorder struct {
	status int
	header http.Header
	body   bytes.Buffer
	wrote  bool
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}

// flushTo writes the recorded response to a real ResponseWriter.
func (r *responseRecorder) flushTo(w http.ResponseWriter) {
	if ct := r.header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body.Bytes())
}
