//go:build qoltanba_functional

// End-to-end tests of the batch and async-job surfaces against the REAL Kalkan
// library: REST /{op}/batch (aggregated + NDJSON), gRPC <Op>Batch streaming, and
// jobs over REST and gRPC. Same environment and build tag as e2e_test.go.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
	grpctransport "github.com/uelnur/qoltanba/internal/transport/grpc"
	"github.com/uelnur/qoltanba/internal/transport/rest"
)

// signN produces n real attached-CMS signatures over distinct payloads.
func signN(t *testing.T, svc *core.Service, n int) [][]byte {
	t.Helper()
	key := testKey(t)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		out, err := svc.Sign(context.Background(), core.SignInput{
			Format: core.FormatCMS, Data: []byte{'d', byte('0' + i)}, Key: key, OutputPEM: true,
		})
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		sigs[i] = out.Signature
	}
	return sigs
}

func TestFunctionalE2E_RESTBatchVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	sigs := signN(t, svc, 3)

	mux := http.NewServeMux()
	mux.Handle("/", rest.New(svc).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	items := make([]map[string]any, len(sigs))
	for i, s := range sigs {
		items[i] = map[string]any{"format": "cms", "signature": s, "inputPem": true}
	}
	body, _ := json.Marshal(map[string]any{"items": items})

	// Aggregated.
	resp, err := http.Post(srv.URL+"/verify/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /verify/batch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var agg core.BatchOutput[core.VerifyOutput]
	if err := json.NewDecoder(resp.Body).Decode(&agg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if agg.Total != 3 || agg.Succeeded != 3 {
		t.Fatalf("summary = %+v, want total=3 succeeded=3", agg)
	}
	for i, r := range agg.Results {
		if r.Status != core.ItemOK || r.Output == nil || !r.Output.Valid {
			t.Fatalf("result[%d] not a valid verify: %+v", i, r)
		}
	}

	// NDJSON stream.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/verify/batch", bytes.NewReader(body))
	req.Header.Set("Accept", "application/x-ndjson")
	sresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream POST: %v", err)
	}
	defer sresp.Body.Close()
	var itemLines, summaryLines int
	sc := bufio.NewScanner(sresp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var line map[string]json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if _, ok := line["index"]; ok {
			itemLines++
		} else if _, ok := line["total"]; ok {
			summaryLines++
		}
	}
	if itemLines != 3 || summaryLines != 1 {
		t.Fatalf("stream had %d items, %d summaries, want 3/1", itemLines, summaryLines)
	}
}

func TestFunctionalE2E_GRPCBatchVerify(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	sigs := signN(t, svc, 2)

	client, done := grpcClient(t, svc, nil)
	defer done()

	items := make([]*pb.VerifyRequest, len(sigs))
	for i, s := range sigs {
		items[i] = &pb.VerifyRequest{Format: pb.SignatureFormat_CMS, Signature: s, InputPem: true}
	}
	stream, err := client.VerifyBatch(context.Background(), &pb.VerifyBatchRequest{Items: items})
	if err != nil {
		t.Fatalf("VerifyBatch: %v", err)
	}
	var valid, summaries int
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch e := ev.GetEvent().(type) {
		case *pb.VerifyBatchEvent_Item:
			if e.Item.GetOutput().GetValid() {
				valid++
			}
		case *pb.VerifyBatchEvent_Summary:
			summaries++
		}
	}
	if valid != 2 || summaries != 1 {
		t.Fatalf("got %d valid items, %d summaries, want 2/1", valid, summaries)
	}
}

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

	// Poll until terminal.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := http.Get(srv.URL + "/jobs/" + view.ID)
		var v jobs.View
		_ = json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		if v.Status.Terminal() {
			view = v
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
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

// startJobManager builds and starts an async-job manager whose executor runs
// through the shared dispatch router over the real service.
func startJobManager(t *testing.T, svc *core.Service) (*jobs.Manager, func()) {
	t.Helper()
	exec := func(ctx context.Context, op string, req json.RawMessage) (any, error) {
		return dispatch.Handle(ctx, svc, op, req)
	}
	mgr := jobs.New(jobs.NewMemStore(), exec, dispatch.Valid, jobs.Config{Workers: 2})
	ctx, cancel := context.WithCancel(context.Background())
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("job manager start: %v", err)
	}
	return mgr, func() { cancel(); mgr.Wait() }
}

// grpcClient dials an in-process gRPC server over the real service, optionally
// with async jobs enabled.
func grpcClient(t *testing.T, svc *core.Service, mgr *jobs.Manager) (pb.SignatureServiceClient, func()) {
	t.Helper()
	var opts []grpctransport.Option
	if mgr != nil {
		opts = append(opts, grpctransport.WithJobs(mgr))
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpclib.NewServer()
	grpctransport.New(svc, opts...).Register(gs)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpclib.NewClient("passthrough:///bufnet",
		grpclib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpclib.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		t.Fatalf("dial: %v", err)
	}
	client := pb.NewSignatureServiceClient(conn)
	return client, func() { _ = conn.Close(); gs.Stop() }
}
