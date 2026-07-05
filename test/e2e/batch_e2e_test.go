//go:build qoltanba_functional

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/transport/rest"
)

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

// TestFunctionalE2E_RESTBatchSign signs several items in one batch and verifies
// each produced signature — the batch surface with real signing, not just verify.
func TestFunctionalE2E_RESTBatchSign(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	mux := http.NewServeMux()
	mux.Handle("/", rest.New(svc).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	items := []map[string]any{
		{"format": "cms", "data": []byte("batch-sign-0"), "key": key, "outputPem": true},
		{"format": "cms", "data": []byte("batch-sign-1"), "key": key, "outputPem": true},
		{"format": "cms", "data": []byte("batch-sign-2"), "key": key, "outputPem": true},
	}
	body, _ := json.Marshal(map[string]any{"items": items})
	resp, err := http.Post(srv.URL+"/sign/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /sign/batch: %v", err)
	}
	defer resp.Body.Close()
	var out core.BatchOutput[core.SignOutput]
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 3 || out.Succeeded != 3 {
		t.Fatalf("summary = %+v, want 3/3", out)
	}
	for i, r := range out.Results {
		if r.Output == nil || len(r.Output.Signature) == 0 {
			t.Fatalf("result[%d] has no signature", i)
		}
		v, err := svc.Verify(context.Background(), core.VerifyInput{
			Format: core.FormatCMS, Signature: r.Output.Signature, InputPEM: true,
		})
		if err != nil || !v.Valid {
			t.Fatalf("result[%d] signature not valid: err=%v valid=%v", i, err, v.Valid)
		}
	}
}

// TestFunctionalE2E_BatchErrorIsolation mixes a good signer with a wrong-password
// one and asserts per-item isolation (continue-on-error) and fail-fast skipping —
// against real key loading.
func TestFunctionalE2E_BatchErrorIsolation(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	good := testKey(t)
	bad := core.KeySpec{Path: &core.PathKey{Path: os.Getenv("QOLTANBA_KEY"), Password: "definitely-wrong"}}

	// continue-on-error: the bad item fails, the good ones succeed.
	out := svc.SignBatch(context.Background(), []core.SignInput{
		{Format: core.FormatCMS, Data: []byte("a"), Key: good, OutputPEM: true},
		{Format: core.FormatCMS, Data: []byte("b"), Key: bad, OutputPEM: true},
		{Format: core.FormatCMS, Data: []byte("c"), Key: good, OutputPEM: true},
	}, core.BatchOptions{Policy: core.PolicyContinue}, nil)
	if out.Succeeded != 2 || out.Failed != 1 {
		t.Fatalf("continue: succeeded=%d failed=%d, want 2/1", out.Succeeded, out.Failed)
	}
	if out.Results[1].Status != core.ItemError || out.Results[1].Error == nil {
		t.Fatalf("bad item not isolated as error: %+v", out.Results[1])
	}

	// fail-fast, concurrency 1: bad first stops the rest.
	ff := svc.SignBatch(context.Background(), []core.SignInput{
		{Format: core.FormatCMS, Data: []byte("x"), Key: bad, OutputPEM: true},
		{Format: core.FormatCMS, Data: []byte("y"), Key: good, OutputPEM: true},
	}, core.BatchOptions{Policy: core.PolicyFailFast, Concurrency: 1}, nil)
	if ff.Results[0].Status != core.ItemError {
		t.Errorf("fail-fast result[0] = %s, want error", ff.Results[0].Status)
	}
	if ff.Results[1].Status != core.ItemSkipped {
		t.Errorf("fail-fast result[1] = %s, want skipped", ff.Results[1].Status)
	}
}
