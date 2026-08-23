package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/idempotency"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func newServer(f *fake.Provider, opts ...core.Option) *httptest.Server {
	svc := core.New(f, opts...)
	mux := http.NewServeMux()
	mux.Handle("/", New(svc).Routes())
	return httptest.NewServer(mux)
}

func post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func TestVerifyEndpoint(t *testing.T) {
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123"}),
	}
	srv := newServer(f)
	defer srv.Close()

	resp := post(t, srv.URL+"/verify", map[string]any{
		"format":    "cms",
		"signature": []byte("sig"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out core.VerifyOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Valid || len(out.Signers) != 1 {
		t.Fatalf("unexpected output %+v", out)
	}
	if out.Signers[0].Certificate.Subject.IIN != "900130300123" {
		t.Errorf("signer IIN = %q", out.Signers[0].Certificate.Subject.IIN)
	}
}

func TestIdempotencyKey_ReplaysResponse(t *testing.T) {
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{Valid: true, Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")}},
		Props:        fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ"}),
	}
	cache := idempotency.New(time.Hour, 16, nil)
	mux := http.NewServeMux()
	mux.Handle("/", New(core.New(f), WithIdempotency(cache)).Routes())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"format": "cms", "signature": []byte("sig")})
	do := func(key string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return resp
	}

	r1 := do("k1")
	defer r1.Body.Close()
	if r1.Header.Get("Idempotency-Replayed") == "true" {
		t.Error("first call must not be a replay")
	}
	b1, _ := io.ReadAll(r1.Body)

	r2 := do("k1")
	defer r2.Body.Close()
	if r2.Header.Get("Idempotency-Replayed") != "true" {
		t.Error("second call with the same key must be a replay")
	}
	b2, _ := io.ReadAll(r2.Body)
	if !bytes.Equal(b1, b2) {
		t.Errorf("replayed body differs:\n%s\n%s", b1, b2)
	}

	// A different key is not a replay.
	r3 := do("k2")
	defer r3.Body.Close()
	if r3.Header.Get("Idempotency-Replayed") == "true" {
		t.Error("a different key must not replay")
	}
}

func TestVerifyEndpoint_Explain(t *testing.T) {
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ"}),
	}
	srv := newServer(f)
	defer srv.Close()

	resp := post(t, srv.URL+"/verify", map[string]any{
		"format":    "cms",
		"signature": []byte("sig"),
		"explain":   true,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out core.VerifyOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Explanation == nil {
		t.Fatal("expected an explanation when explain=true")
	}
	if len(out.Explanation.Steps) == 0 {
		t.Error("explanation has no steps")
	}
	if out.Explanation.Steps[0].Step != "signature" {
		t.Errorf("first step = %q, want signature", out.Explanation.Steps[0].Step)
	}
}

func TestVerifyAtEndpoint(t *testing.T) {
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{
			"NOTBEFORE": "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":  "01.01.2023 00:00:00 +00:00",
		}),
		ValidateResult: provider.ValidateResult{Status: provider.StatusGood},
	}
	srv := newServer(f, core.WithClock(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }))
	defer srv.Close()

	resp := post(t, srv.URL+"/verify/at", map[string]any{
		"format":    "cms",
		"signature": []byte("sig"),
		"at":        "2022-06-01T00:00:00Z",
		"method":    "ocsp",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out core.VerifyAtOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.ValidAt || !out.Determinate || len(out.Signers) != 1 {
		t.Fatalf("unexpected output %+v", out)
	}
}

func TestVerifyAtEndpoint_FutureRejected(t *testing.T) {
	srv := newServer(&fake.Provider{}, core.WithClock(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }))
	defer srv.Close()
	resp := post(t, srv.URL+"/verify/at", map[string]any{
		"format": "cms", "signature": []byte("x"), "at": "2027-01-01T00:00:00Z",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSignEndpoint_VerifyOnlyRejected(t *testing.T) {
	srv := newServer(&fake.Provider{}, core.WithVerifyOnly(true))
	defer srv.Close()

	resp := post(t, srv.URL+"/sign", map[string]any{"format": "cms", "data": []byte("x"),
		"key": map[string]any{"path": map[string]any{"path": "/k.p12"}}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var body errorBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Kind != "invalid" {
		t.Errorf("error kind = %q, want invalid", body.Error.Kind)
	}
}

func TestBadFormatIs400(t *testing.T) {
	srv := newServer(&fake.Provider{})
	defer srv.Close()
	resp := post(t, srv.URL+"/verify", map[string]any{"format": "bogus", "signature": []byte("x")})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestReadyz(t *testing.T) {
	h := Observability(func() bool { return true }, func() StatusInfo { return StatusInfo{Service: "x"} })
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz status = %d, want 200", resp.StatusCode)
	}
}
