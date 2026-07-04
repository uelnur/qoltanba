package trust

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/pki"
)

// Refresher periodically rebuilds a live Store's anchors from its sources (the CA
// directory plus the official RK CA registry), so a long-running service picks up
// registry changes and new local CA files without a restart. It is best-effort:
// a rebuild that would yield an empty set (e.g. every fetch failed transiently)
// keeps the last-good anchors rather than wiping trust.
type Refresher struct {
	store *Store
	caDir string
	refs  []pki.CACertRef
	fetch FetchFunc
	log   *slog.Logger

	mu     sync.Mutex
	status RefreshStatus
}

// RefreshStatus is a snapshot of the last refresh, surfaced at /statusz.
type RefreshStatus struct {
	Enabled     bool   `json:"enabled"`
	IntervalSec int    `json:"intervalSeconds,omitempty"`
	LastAt      string `json:"lastAt,omitempty"` // RFC3339, empty until first refresh
	AnchorCount int    `json:"anchorCount"`
	LastErrors  int    `json:"lastErrors"` // failed sources in the last rebuild
}

// NewRefresher builds a Refresher over an existing live Store. refs are the RK CA
// references to fetch (empty to rebuild only from caDir); fetch downloads a CA
// (use HTTPFetcher). The store's initial anchors are reported until the first
// refresh runs.
func NewRefresher(store *Store, caDir string, refs []pki.CACertRef, fetch FetchFunc, log *slog.Logger) *Refresher {
	return &Refresher{
		store: store, caDir: caDir, refs: refs, fetch: fetch, log: log,
		status: RefreshStatus{AnchorCount: store.Count()},
	}
}

// Refresh rebuilds the anchor set from all sources and atomically swaps it into
// the live store. It records status regardless of outcome. When the rebuild would
// produce zero anchors but the store currently holds some, it skips the swap and
// keeps the last-good set (transient-failure protection).
func (r *Refresher) Refresh(ctx context.Context) {
	fresh := &Store{}
	var errs []error
	if built, err := LoadDir(r.caDir); err != nil {
		errs = append(errs, err)
	} else {
		fresh.anchors = append(fresh.anchors, built.Anchors()...)
	}
	if len(r.refs) > 0 {
		errs = append(errs, fresh.LoadRegistry(ctx, r.refs, r.fetch)...)
	}

	count := fresh.Count()
	kept := count == 0 && r.store.Count() > 0
	if !kept {
		r.store.replace(fresh.anchors)
	} else if r.log != nil {
		r.log.Warn("trust refresh: rebuild yielded no anchors, keeping last-good set", "errors", len(errs))
	}

	r.mu.Lock()
	r.status.LastAt = nowRFC3339()
	r.status.AnchorCount = r.store.Count()
	r.status.LastErrors = len(errs)
	r.mu.Unlock()

	if r.log != nil && len(errs) > 0 {
		r.log.Warn("trust refresh: some sources failed", "failed", len(errs), "anchors", r.store.Count())
	}
}

// Run refreshes on interval until ctx is canceled. The first refresh happens
// after one interval (startup already loaded the initial set). interval<=0 is a
// no-op (auto-refresh disabled).
func (r *Refresher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	r.mu.Lock()
	r.status.Enabled = true
	r.status.IntervalSec = int(interval / time.Second)
	r.mu.Unlock()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Refresh(ctx)
		}
	}
}

// Status returns a snapshot of the last refresh for /statusz.
func (r *Refresher) Status() RefreshStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// core.TrustStore compliance check: the Store behind a Refresher is the port.
var _ core.TrustStore = (*Store)(nil)

// nowRFC3339 is a package var so tests can pin time; production uses the wall
// clock. Kept minimal — the Refresher only needs a timestamp string.
var nowRFC3339 = func() string { return time.Now().UTC().Format(time.RFC3339) }
