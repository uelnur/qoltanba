package rest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func TestValidateBatch_Aggregated(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	srv := newServer(f)
	defer srv.Close()

	resp := post(t, srv.URL+"/cert/validate/batch", map[string]any{
		"items": []map[string]any{
			{"cert": []byte("a"), "encoding": "der"},
			{"cert": []byte("b"), "encoding": "der"},
			{"cert": []byte("c"), "encoding": "der"},
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out core.BatchOutput[core.ValidateOutput]
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Total != 3 || out.Succeeded != 3 || out.Failed != 0 {
		t.Fatalf("summary = %+v, want 3/3/0", out)
	}
	for i, r := range out.Results {
		if r.Index != i || r.Status != core.ItemOK || r.Output == nil {
			t.Errorf("result[%d] = %+v", i, r)
		}
	}
}

func TestValidateBatch_NDJSONStream(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	srv := newServer(f)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"items": []map[string]any{
			{"cert": []byte("a"), "encoding": "der"},
			{"cert": []byte("b"), "encoding": "der"},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/cert/validate/batch", bytes.NewReader(body))
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content-type = %q", ct)
	}

	var items, summaries int
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var line map[string]json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", sc.Text(), err)
		}
		if _, ok := line["index"]; ok {
			items++
		} else if _, ok := line["total"]; ok {
			summaries++
		}
	}
	if items != 2 || summaries != 1 {
		t.Fatalf("stream had %d item lines, %d summary lines, want 2/1", items, summaries)
	}
}

func TestBatch_MalformedItemRejected(t *testing.T) {
	srv := newServer(&fake.Provider{})
	defer srv.Close()

	resp := post(t, srv.URL+"/verify/batch", map[string]any{
		"items": []map[string]any{
			{"format": "cms", "signature": []byte("s")},
			{"format": "bogus", "signature": []byte("s")}, // invalid format aborts the batch
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
