package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
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
