//go:build qoltanba_functional

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/transport/rest"
)

func TestFunctionalE2E_RESTJobVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	sig := signN(t, svc, 1)[0]

	mgr, stop := startJobManager(t, svc)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/", rest.New(svc, rest.WithJobs(mgr)).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	reqBody, _ := json.Marshal(map[string]any{
		"op":      "verify",
		"request": map[string]any{"format": "cms", "signature": sig, "inputPem": true},
	})
	resp, err := http.Post(srv.URL+"/jobs", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /jobs: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202", resp.StatusCode)
	}
	var view jobs.View
	_ = json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()

	view = pollJob(t, srv.URL, view.ID)
	if view.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s, want succeeded", view.Status)
	}

	rr, err := http.Get(srv.URL + "/jobs/" + view.ID + "/result")
	if err != nil {
		t.Fatalf("GET result: %v", err)
	}
	defer rr.Body.Close()
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("result status = %d, want 200", rr.StatusCode)
	}
	var out core.VerifyOutput
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !out.Valid {
		t.Fatalf("job verify not valid; libError=%+v", out.LibError)
	}
}

func TestFunctionalE2E_GRPCJobVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	sig := signN(t, svc, 1)[0]

	mgr, stop := startJobManager(t, svc)
	defer stop()

	client, done := grpcClient(t, svc, mgr)
	defer done()
	ctx := context.Background()

	reqJSON, _ := json.Marshal(map[string]any{"format": "cms", "signature": sig, "inputPem": true})
	sub, err := client.SubmitJob(ctx, &pb.SubmitJobRequest{Op: "verify", Request: reqJSON})
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		js, err := client.GetJob(ctx, &pb.JobId{Id: sub.GetId()})
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		status = js.GetStatus()
		if status == "succeeded" || status == "failed" || status == "canceled" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if status != "succeeded" {
		t.Fatalf("job status = %s, want succeeded", status)
	}
	res, err := client.GetJobResult(ctx, &pb.JobId{Id: sub.GetId()})
	if err != nil {
		t.Fatalf("GetJobResult: %v", err)
	}
	var out core.VerifyOutput
	if err := json.Unmarshal(res.GetResult(), &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !out.Valid {
		t.Fatalf("gRPC job verify not valid; libError=%+v", out.LibError)
	}
}

// TestFunctionalE2E_JobSign runs a real sign as an async job and verifies the
// signature the job produced.
func TestFunctionalE2E_JobSign(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	mgr, stop := startJobManager(t, svc)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/", rest.New(svc, rest.WithJobs(mgr)).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	reqBody, _ := json.Marshal(map[string]any{
		"op":      "sign",
		"request": map[string]any{"format": "cms", "data": []byte("job-sign"), "key": key, "outputPem": true},
	})
	resp, err := http.Post(srv.URL+"/jobs", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /jobs: %v", err)
	}
	var view jobs.View
	_ = json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()

	view = pollJob(t, srv.URL, view.ID)
	if view.Status != jobs.StatusSucceeded {
		t.Fatalf("job status = %s, want succeeded", view.Status)
	}
	rr, err := http.Get(srv.URL + "/jobs/" + view.ID + "/result")
	if err != nil {
		t.Fatalf("GET result: %v", err)
	}
	defer rr.Body.Close()
	var out core.SignOutput
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	v, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatCMS, Signature: out.Signature, InputPEM: true})
	if err != nil || !v.Valid {
		t.Fatalf("job-produced signature not valid: err=%v valid=%v", err, v.Valid)
	}
}

// pollJob polls GET /jobs/{id} over REST until the job is terminal or the
// deadline passes.
func pollJob(t *testing.T, baseURL, id string) jobs.View {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var v jobs.View
	for time.Now().Before(deadline) {
		r, err := http.Get(baseURL + "/jobs/" + id)
		if err != nil {
			t.Fatalf("GET job: %v", err)
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		if v.Status.Terminal() {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish in time", id)
	return v
}
