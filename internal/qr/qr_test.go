package qr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/oidc"
)

var baseTime = time.Unix(1_700_000_000, 0).UTC()

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// fakeVerifier returns a fixed verification outcome. A valid signer carries a
// minimal claim set so the flow can extract identity.
type fakeVerifier struct {
	out      core.VerifyOutput
	err      error
	validate core.ValidateOutput
}

func (f *fakeVerifier) Verify(context.Context, core.VerifyInput) (core.VerifyOutput, error) {
	return f.out, f.err
}
func (f *fakeVerifier) Validate(context.Context, core.ValidateInput) (core.ValidateOutput, error) {
	return f.validate, nil
}

type fakeIssuer struct{ called bool }

func (f *fakeIssuer) IssueTokens(_ context.Context, claims core.Claims, clientID, nonce string) (oidc.TokenResponse, error) {
	f.called = true
	return oidc.TokenResponse{IDToken: "id." + claims.Sub + "." + nonce, AccessToken: "acc", TokenType: "Bearer", ExpiresIn: 3600}, nil
}

func validOutput() core.VerifyOutput {
	return core.VerifyOutput{
		Valid: true,
		Signers: []core.Signer{{
			Certificate: core.Certificate{PEM: []byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
			Claims:      &core.Claims{Sub: "900130300123", Name: "ТЕСТ", IIN: "900130300123"},
		}},
	}
}

func newOrch(v Verifier, clk *fakeClock, opts ...Option) *Orchestrator {
	profiles := map[Profile]Profiler{
		ProfileAgnostic: NewAgnosticProfile(),
		ProfileEGov:     NewEGovProfile(EGovConfig{Organization: "ACME"}),
	}
	base := []Option{WithClock(clk.Now)}
	return New(v, NewMemStore(), profiles, Config{}, append(base, opts...)...)
}

func TestAgnosticSignFlow(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk)

	res, err := o.Create(context.Background(), CreateRequest{Data: []byte("doc")}, "https://c.kz/esign")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Status != string(StatusPending) || res.QR == "" || res.DataURL == "" {
		t.Fatalf("create response = %+v", res)
	}
	if !strings.HasPrefix(res.DataURL, "https://c.kz/esign/qr/a/") {
		t.Errorf("dataURL = %q, want public base + /qr/a/", res.DataURL)
	}
	// QR is a decodable PNG.
	raw, err := base64.StdEncoding.DecodeString(res.QR)
	if err != nil {
		t.Fatalf("qr base64: %v", err)
	}
	if _, err := png.Decode(strings.NewReader(string(raw))); err != nil {
		t.Fatalf("qr png decode: %v", err)
	}

	// App fetches the data-to-sign.
	if _, err := o.AppData(context.Background(), res.SessionID); err != nil {
		t.Fatalf("app data: %v", err)
	}
	// App submits a signature → verified.
	body, _ := json.Marshal(map[string]any{"signature": []byte("sig")})
	if err := o.SubmitSignature(context.Background(), res.SessionID, body); err != nil {
		t.Fatalf("submit: %v", err)
	}
	v, err := o.Get(context.Background(), res.SessionID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v.Status != string(StatusVerified) {
		t.Fatalf("status = %q, want verified", v.Status)
	}
	var sr SignResult
	if err := json.Unmarshal(v.Result, &sr); err != nil || !sr.Valid || sr.Claims.Sub != "900130300123" {
		t.Errorf("result = %s (err %v)", v.Result, err)
	}
}

func TestSingleUse(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk)
	res, _ := o.Create(context.Background(), CreateRequest{Data: []byte("doc")}, "https://c.kz")
	body, _ := json.Marshal(map[string]any{"signature": []byte("sig")})
	if err := o.SubmitSignature(context.Background(), res.SessionID, body); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if err := o.SubmitSignature(context.Background(), res.SessionID, body); !errors.Is(err, ErrSessionUsed) {
		t.Errorf("second submit err = %v, want ErrSessionUsed", err)
	}
}

func TestExpiry(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk)
	res, _ := o.Create(context.Background(), CreateRequest{Data: []byte("doc"), TTLSeconds: 60}, "https://c.kz")
	clk.t = clk.t.Add(2 * time.Minute)

	if _, err := o.AppData(context.Background(), res.SessionID); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("app data after expiry = %v, want ErrSessionExpired", err)
	}
	v, _ := o.Get(context.Background(), res.SessionID)
	if v.Status != string(StatusExpired) {
		t.Errorf("status = %q, want expired", v.Status)
	}
}

func TestSignatureRejected(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: core.VerifyOutput{Valid: false}}, clk)
	res, _ := o.Create(context.Background(), CreateRequest{Data: []byte("doc")}, "https://c.kz")
	body, _ := json.Marshal(map[string]any{"signature": []byte("bad")})
	if err := o.SubmitSignature(context.Background(), res.SessionID, body); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("submit err = %v, want ErrSignatureRejected", err)
	}
	v, _ := o.Get(context.Background(), res.SessionID)
	if v.Status != string(StatusFailed) || v.Error == nil {
		t.Errorf("view = %+v, want failed with error", v)
	}
}

func TestAuthMode(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	iss := &fakeIssuer{}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk, WithTokenIssuer(iss))

	res, err := o.Create(context.Background(), CreateRequest{Mode: ModeAuth, ClientID: "app1", Nonce: "n1"}, "https://c.kz")
	if err != nil {
		t.Fatalf("create auth: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"signature": []byte("sig")})
	if err := o.SubmitSignature(context.Background(), res.SessionID, body); err != nil {
		t.Fatalf("submit: %v", err)
	}
	v, _ := o.Get(context.Background(), res.SessionID)
	var tok oidc.TokenResponse
	if err := json.Unmarshal(v.Result, &tok); err != nil {
		t.Fatalf("token result: %v", err)
	}
	if !iss.called || tok.IDToken != "id.900130300123.n1" {
		t.Errorf("tokens = %+v (issuer called=%v)", tok, iss.called)
	}
}

func TestAuthModeRequiresIssuer(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk) // no WithTokenIssuer
	if _, err := o.Create(context.Background(), CreateRequest{Mode: ModeAuth}, "https://c.kz"); !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("create auth without issuer = %v, want ErrAuthUnavailable", err)
	}
}

func TestEGovAppDataShape(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk)
	res, err := o.Create(context.Background(), CreateRequest{
		Profile: ProfileEGov, SignMethod: "CMS_SIGN_ONLY",
		Documents: []Document{{NameRu: "Договор", Data: []byte("pdfbytes"), MIME: "@file/pdf"}},
	}, "https://c.kz")
	if err != nil {
		t.Fatalf("create egov: %v", err)
	}
	if res.Payload != "https://c.kz/qr/a/"+res.SessionID {
		t.Errorf("egov payload = %q", res.Payload)
	}
	data, err := o.AppData(context.Background(), res.SessionID)
	if err != nil {
		t.Fatalf("app data: %v", err)
	}
	b, _ := json.Marshal(data)
	if !strings.Contains(string(b), `"signMethod":"CMS_SIGN_ONLY"`) || !strings.Contains(string(b), `"documentsToSign"`) {
		t.Errorf("egov app data = %s", b)
	}
}

func TestRelayProfile(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString([]byte("relay-cms-sig"))
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/egovQr":
			base := "http://" + r.Host
			_, _ = w.Write([]byte(`{"qrCode":"QR123","dataURL":"` + base + `/data","signURL":"` + base + `/sign","eGovMobileLaunchLink":"lk"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/data":
			_, _ = w.Write([]byte(`{"signURL":"http://` + r.Host + `/sign"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/sign":
			polls++
			if polls < 2 {
				_, _ = w.Write([]byte(`{"status":"PENDING","documentsToSign":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"DONE","documentsToSign":[{"cms":"` + sig + `"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	clk := &fakeClock{t: baseTime}
	profiles := map[Profile]Profiler{ProfileRelay: NewRelayProfile(RelayConfig{BaseURL: srv.URL, Client: srv.Client()})}
	o := New(&fakeVerifier{out: validOutput()}, NewMemStore(), profiles,
		Config{DefaultProfile: ProfileRelay}, WithClock(clk.Now))

	res, err := o.Create(context.Background(), CreateRequest{Data: []byte("doc")}, "")
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if res.Payload != "QR123" || res.EGovMobileLink != "lk" {
		t.Fatalf("relay create = %+v", res)
	}
	// First poll: still pending.
	if v, _ := o.Get(context.Background(), res.SessionID); v.Status != string(StatusPending) {
		t.Fatalf("first poll status = %q, want pending", v.Status)
	}
	// Second poll: upstream returns the signature → verified.
	v, _ := o.Get(context.Background(), res.SessionID)
	if v.Status != string(StatusVerified) {
		t.Fatalf("second poll status = %q, want verified", v.Status)
	}
}

func TestUnsupportedProfile(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk) // relay not registered
	if _, err := o.Create(context.Background(), CreateRequest{Profile: ProfileRelay, Data: []byte("x")}, "https://c.kz"); !errors.Is(err, ErrUnsupportedProfile) {
		t.Errorf("create relay (unregistered) = %v, want ErrUnsupportedProfile", err)
	}
}

func TestNoData(t *testing.T) {
	clk := &fakeClock{t: baseTime}
	o := newOrch(&fakeVerifier{out: validOutput()}, clk)
	if _, err := o.Create(context.Background(), CreateRequest{Mode: ModeSign}, "https://c.kz"); !errors.Is(err, ErrNoData) {
		t.Errorf("create sign without data = %v, want ErrNoData", err)
	}
}
