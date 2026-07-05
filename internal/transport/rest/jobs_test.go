package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
)

// newJobServer wires a REST server whose job executor runs through the same
// dispatch router the sync endpoints use.
func newJobServer(t *testing.T, f *fake.Provider) *httptest.Server {
	t.Helper()
	svc := core.New(f)
	exec := func(ctx context.Context, op string, req json.RawMessage) (any, error) {
		return dispatch.Handle(ctx, svc, op, req)
	}
	mgr := jobs.New(jobs.NewMemStore(), exec, dispatch.Valid, jobs.Config{Workers: 2})
	ctx, cancel := context.WithCancel(context.Background())
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { cancel(); mgr.Wait() })

	mux := http.NewServeMux()
	mux.Handle("/", New(svc, WithJobs(mgr)).Routes())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestJobLifecycle(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	srv := newJobServer(t, f)

	// Submit.
	resp := post(t, srv.URL+"/jobs", map[string]any{
		"op":      "cert-validate",
		"request": map[string]any{"cert": []byte("c"), "encoding": "der"},
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc == "" {
		t.Error("missing Location header")
	}
	var submitted jobs.View
	_ = json.NewDecoder(resp.Body).Decode(&submitted)
	resp.Body.Close()
	if submitted.ID == "" {
		t.Fatal("no job id returned")
	}

	// Poll status until terminal.
	deadline := time.Now().Add(2 * time.Second)
	var status jobs.Status
	for time.Now().Before(deadline) {
		r, err := http.Get(srv.URL + "/jobs/" + submitted.ID)
		if err != nil {
			t.Fatalf("get status: %v", err)
		}
		var v jobs.View
		_ = json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		status = v.Status
		if v.Status.Terminal() {
			break
		}
		time.Sleep(3 * time.Millisecond)
	}
	if status != jobs.StatusSucceeded {
		t.Fatalf("final status = %s, want succeeded", status)
	}

	// Fetch the result.
	r, err := http.Get(srv.URL + "/jobs/" + submitted.ID + "/result")
	if err != nil {
		t.Fatalf("get result: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("result status = %d, want 200", r.StatusCode)
	}
	var out core.ValidateOutput
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if out.Status.Revoked {
		t.Errorf("unexpected revoked status")
	}
}

func TestJob_NotFound(t *testing.T) {
	srv := newJobServer(t, &fake.Provider{})
	r, err := http.Get(srv.URL + "/jobs/deadbeef")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", r.StatusCode)
	}
}

func TestJob_UnknownOpRejected(t *testing.T) {
	srv := newJobServer(t, &fake.Provider{})
	resp := post(t, srv.URL+"/jobs", map[string]any{"op": "nope", "request": map[string]any{}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
