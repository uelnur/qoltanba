package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/pki"
)

func selfSignedDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := caTmpl(cn)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func TestRefresh_RebuildsFromRegistry(t *testing.T) {
	der := selfSignedDER(t, "Refresh Root")
	refs := []pki.CACertRef{{Label: "root", URL: "https://x/root.cer"}}
	fetch := func(_ context.Context, _ string) ([]byte, bool) { return der, true }

	store := Empty()
	r := NewRefresher(store, "", refs, fetch, nil)
	r.Refresh(context.Background())

	if got := store.Count(); got != 1 {
		t.Fatalf("anchors = %d, want 1", got)
	}
	st := r.Status()
	if st.AnchorCount != 1 || st.LastErrors != 0 || st.LastAt == "" {
		t.Errorf("status = %+v, want 1 anchor, 0 errors, non-empty lastAt", st)
	}
}

func TestRefresh_KeepsLastGoodOnEmptyRebuild(t *testing.T) {
	der := selfSignedDER(t, "Sticky Root")
	refs := []pki.CACertRef{{Label: "root", URL: "https://x/root.cer"}}

	// First refresh succeeds and populates one anchor.
	ok := true
	fetch := func(_ context.Context, _ string) ([]byte, bool) {
		if ok {
			return der, true
		}
		return nil, false
	}
	store := Empty()
	r := NewRefresher(store, "", refs, fetch, nil)
	r.Refresh(context.Background())
	if store.Count() != 1 {
		t.Fatalf("setup: anchors = %d, want 1", store.Count())
	}

	// Second refresh: every fetch fails → rebuild is empty → keep last-good.
	ok = false
	r.Refresh(context.Background())
	if store.Count() != 1 {
		t.Errorf("anchors = %d after failed refresh, want kept at 1", store.Count())
	}
	if st := r.Status(); st.LastErrors == 0 {
		t.Errorf("status LastErrors = 0, want the failed source counted")
	}
}

func TestRun_DisabledIsNoOp(t *testing.T) {
	store := Empty()
	r := NewRefresher(store, "", nil, nil, nil)
	// interval<=0 must return immediately without touching the ticker.
	r.Run(context.Background(), 0)
	if st := r.Status(); st.Enabled {
		t.Errorf("status Enabled = true, want false for a disabled refresher")
	}
}

func TestRun_CancelStops(t *testing.T) {
	der := selfSignedDER(t, "Run Root")
	refs := []pki.CACertRef{{Label: "root", URL: "https://x/root.cer"}}
	fetch := func(_ context.Context, _ string) ([]byte, bool) { return der, true }
	store := Empty()
	r := NewRefresher(store, "", refs, fetch, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
	if st := r.Status(); !st.Enabled || st.IntervalSec != 3600 {
		t.Errorf("status = %+v, want Enabled with 3600s interval", st)
	}
}
