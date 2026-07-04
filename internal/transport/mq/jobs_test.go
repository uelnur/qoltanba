package mq

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
)

func newJobProcessor(t *testing.T, f *fake.Provider) *Processor {
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
	return NewProcessor(svc, nil, WithJobs(mgr))
}

func TestProcess_JobLifecycleOverMQ(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	p := newJobProcessor(t, f)

	// Submit.
	submitBody := `{"op":"job-submit","request":{"op":"cert-validate","request":{"cert":"Yw==","encoding":"der"}}}`
	r, _ := run(t, p, submitBody, "").only(t)
	if r.Error != nil {
		t.Fatalf("submit error: %+v", r.Error)
	}
	var view jobs.View
	if err := json.Unmarshal(r.Result, &view); err != nil || view.ID == "" {
		t.Fatalf("submit reply = %s, err %v", r.Result, err)
	}

	// Poll status until terminal.
	deadline := time.Now().Add(2 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		sr, _ := run(t, p, `{"op":"job-status","request":{"id":"`+view.ID+`"}}`, "").only(t)
		var v jobs.View
		_ = json.Unmarshal(sr.Result, &v)
		status = string(v.Status)
		if v.Status.Terminal() {
			break
		}
		time.Sleep(3 * time.Millisecond)
	}
	if status != "succeeded" {
		t.Fatalf("final status = %s, want succeeded", status)
	}

	// Result.
	rr, _ := run(t, p, `{"op":"job-result","request":{"id":"`+view.ID+`"}}`, "").only(t)
	if rr.Error != nil {
		t.Fatalf("result error: %+v", rr.Error)
	}
	var res jobResultMsg
	if err := json.Unmarshal(rr.Result, &res); err != nil {
		t.Fatalf("decode job-result: %v", err)
	}
	if res.Status != "succeeded" {
		t.Fatalf("result status = %s", res.Status)
	}
	var out core.ValidateOutput
	if err := json.Unmarshal(res.Result, &out); err != nil {
		t.Fatalf("decode op output: %v", err)
	}
	if out.Status.Revoked {
		t.Errorf("unexpected revoked")
	}
}

func TestProcess_JobDisabledWhenNoManager(t *testing.T) {
	p := NewProcessor(core.New(&fake.Provider{}), nil) // no WithJobs
	r, _ := run(t, p, `{"op":"job-submit","request":{"op":"verify","request":{}}}`, "").only(t)
	if r.Error == nil || r.Error.Kind != "unsupported" {
		t.Fatalf("error = %+v, want unsupported", r.Error)
	}
}

func TestProcess_JobNotFoundOverMQ(t *testing.T) {
	p := newJobProcessor(t, &fake.Provider{})
	r, _ := run(t, p, `{"op":"job-status","request":{"id":"nope"}}`, "").only(t)
	if r.Error == nil || r.Error.Kind != "invalid" {
		t.Fatalf("error = %+v, want invalid (job not found)", r.Error)
	}
}
