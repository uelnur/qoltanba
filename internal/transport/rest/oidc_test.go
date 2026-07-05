package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func newOIDCServer(t *testing.T) (*httptest.Server, *oidc.Provider) {
	t.Helper()
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123"}),
	}
	svc := core.New(f)
	signer, err := oidc.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	prov := oidc.New(svc, signer, oidc.NewMemStore(), oidc.Config{Issuer: "https://auth.example.kz"})
	mux := http.NewServeMux()
	mux.Handle("/", New(svc, WithOIDC(prov)).Routes())
	return httptest.NewServer(mux), prov
}

func TestOIDC_Discovery(t *testing.T) {
	srv, _ := newOIDCServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var doc oidc.DiscoveryDoc
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc.Issuer != "https://auth.example.kz" || doc.JWKSURI == "" {
		t.Errorf("discovery = %+v", doc)
	}
}

func TestOIDC_JWKS(t *testing.T) {
	srv, _ := newOIDCServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/oidc/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	var set oidc.JWKSet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	if len(set.Keys) != 1 || set.Keys[0].Kty != "RSA" {
		t.Errorf("jwks = %+v", set)
	}
}

func TestOIDC_ChallengeVerifyFlow(t *testing.T) {
	srv, prov := newOIDCServer(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/oidc/challenge", map[string]any{"nonce": "rp-nonce"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d", resp.StatusCode)
	}
	var ch oidc.ChallengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&ch)
	if ch.ChallengeID == "" || ch.Data == "" {
		t.Fatalf("challenge = %+v", ch)
	}

	vresp := post(t, srv.URL+"/oidc/verify", map[string]any{
		"challengeId": ch.ChallengeID,
		"signature":   []byte("cms-signature"),
	})
	defer vresp.Body.Close()
	if vresp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d", vresp.StatusCode)
	}
	var tok oidc.TokenResponse
	_ = json.NewDecoder(vresp.Body).Decode(&tok)
	if tok.IDToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token = %+v", tok)
	}
	claims, err := prov.Signer().Verify(tok.IDToken, time.Now())
	if err != nil {
		t.Fatalf("id_token verify: %v", err)
	}
	if claims["sub"] != "900130300123" || claims["nonce"] != "rp-nonce" {
		t.Errorf("claims = %+v", claims)
	}

	// UserInfo with the access token echoes claims.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d", uresp.StatusCode)
	}
}

func TestOIDC_VerifyUnknownChallenge(t *testing.T) {
	srv, _ := newOIDCServer(t)
	defer srv.Close()
	resp := post(t, srv.URL+"/oidc/verify", map[string]any{
		"challengeId": "does-not-exist",
		"signature":   []byte("cms"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe oauthError
	_ = json.NewDecoder(resp.Body).Decode(&oe)
	if oe.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oe.Error)
	}
}

func TestOIDC_UserInfoMissingBearer(t *testing.T) {
	srv, _ := newOIDCServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/oidc/userinfo")
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
