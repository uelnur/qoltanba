package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider/fake"
	"github.com/uelnur/qoltanba/internal/qr"
)

// fakeQRVerifier accepts any signature as a valid signer with a fixed identity.
type fakeQRVerifier struct{}

func (fakeQRVerifier) Verify(context.Context, core.VerifyInput) (core.VerifyOutput, error) {
	return core.VerifyOutput{Valid: true, Signers: []core.Signer{{
		Certificate: core.Certificate{PEM: []byte("x")},
		Claims:      &core.Claims{Sub: "900130300123"},
	}}}, nil
}

func (fakeQRVerifier) Validate(context.Context, core.ValidateInput) (core.ValidateOutput, error) {
	return core.ValidateOutput{}, nil
}

func newQRServer(t *testing.T) *httptest.Server {
	t.Helper()
	orch := qr.New(fakeQRVerifier{}, qr.NewMemStore(),
		map[qr.Profile]qr.Profiler{qr.ProfileAgnostic: qr.NewAgnosticProfile()}, qr.Config{})
	svc := core.New(&fake.Provider{})
	return httptest.NewServer(New(svc, WithQR(orch, "https://c.kz/esign")).Routes())
}

func TestQREndpoints(t *testing.T) {
	srv := newQRServer(t)
	defer srv.Close()

	// Create a session.
	resp := post(t, srv.URL+"/qr/sessions", map[string]any{"data": []byte("doc")})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}
	var created qr.CreateResponse
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.QR == "" || created.SessionID == "" {
		t.Fatalf("create response = %+v", created)
	}

	// App fetches the data-to-sign.
	dr, err := http.Get(srv.URL + "/qr/a/" + created.SessionID)
	if err != nil || dr.StatusCode != http.StatusOK {
		t.Fatalf("app data GET = %v status %d", err, dr.StatusCode)
	}
	dr.Body.Close()

	// App submits the signature.
	sr := post(t, srv.URL+"/qr/a/"+created.SessionID, map[string]any{"signature": []byte("sig")})
	if sr.StatusCode != http.StatusOK {
		t.Fatalf("submit status = %d, want 200", sr.StatusCode)
	}
	sr.Body.Close()

	// Consumer polls the verified result.
	pr, _ := http.Get(srv.URL + "/qr/sessions/" + created.SessionID)
	var view qr.View
	_ = json.NewDecoder(pr.Body).Decode(&view)
	pr.Body.Close()
	if view.Status != "verified" {
		t.Fatalf("status = %q, want verified", view.Status)
	}

	// Unknown session → 404.
	nr, _ := http.Get(srv.URL + "/qr/sessions/deadbeef")
	if nr.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session status = %d, want 404", nr.StatusCode)
	}
	nr.Body.Close()
}

func TestPublicBaseURL(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		headers    map[string]string
		host       string
		want       string
	}{
		{"configured wins", "https://cfg.kz/x", map[string]string{"X-Forwarded-Host": "other.kz"}, "h", "https://cfg.kz/x"},
		{"forwarded", "", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "pub.kz", "X-Forwarded-Prefix": "/esign/"}, "internal", "https://pub.kz/esign"},
		{"forwarded list", "", map[string]string{"X-Forwarded-Proto": "https, http", "X-Forwarded-Host": "a.kz, b.kz"}, "internal", "https://a.kz"},
		{"host fallback", "", nil, "svc:8080", "http://svc:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/qr/sessions", nil)
			r.Host = c.host
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := publicBaseURL(r, c.configured); got != c.want {
				t.Errorf("publicBaseURL = %q, want %q", got, c.want)
			}
		})
	}
}
