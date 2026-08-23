package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

func pkcePair(verifier string) (challenge string) {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestParseClients(t *testing.T) {
	got, err := ParseClients([]string{
		"web|s3cret|https://app.kz/callback|https://app.kz/callback2",
		"spa||https://spa.kz/cb",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("clients = %d, want 2", len(got))
	}
	if c := got["web"]; c.Secret != "s3cret" || len(c.RedirectURIs) != 2 {
		t.Errorf("confidential client parsed wrong: %+v", c)
	}
	if c := got["spa"]; c.Secret != "" || len(c.RedirectURIs) != 1 {
		t.Errorf("public client parsed wrong: %+v", c)
	}

	for _, bad := range []string{"web", "web|secret", "|secret|https://a", "web|secret|"} {
		if _, err := ParseClients([]string{bad}); err == nil {
			t.Errorf("ParseClients(%q) should fail", bad)
		}
	}
}

// TestValidateAuthorize covers the checks that stand between a browser redirect
// and an account takeover.
func TestValidateAuthorize(t *testing.T) {
	p := newTestProviderWithClients(t)
	base := AuthorizeRequest{
		ClientID: "spa", RedirectURI: "https://spa.kz/cb", ResponseType: "code",
		CodeChallenge: pkcePair("v"), CodeChallengeMethod: "S256",
	}

	if _, err := p.ValidateAuthorize(base); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*AuthorizeRequest)
		want error
	}{
		{"unknown client", func(r *AuthorizeRequest) { r.ClientID = "nope" }, ErrUnknownClient},
		{"unregistered redirect", func(r *AuthorizeRequest) { r.RedirectURI = "https://evil.kz/cb" }, ErrRedirectMismatch},
		{"redirect prefix is not enough", func(r *AuthorizeRequest) { r.RedirectURI = "https://spa.kz/cb/../evil" }, ErrRedirectMismatch},
		{"implicit flow refused", func(r *AuthorizeRequest) { r.ResponseType = "token" }, ErrUnsupportedFlow},
		{"public client without PKCE", func(r *AuthorizeRequest) { r.CodeChallenge = "" }, ErrPKCERequired},
		{"plain PKCE refused", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, ErrPKCERequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mut(&req)
			if _, err := p.ValidateAuthorize(req); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestAuthorizationCodeRoundTrip walks the whole browser leg: authorize, sign,
// redirect with a code, exchange it for tokens.
func TestAuthorizationCodeRoundTrip(t *testing.T) {
	p := newTestProviderWithClients(t)
	verifier := "a-code-verifier-of-sufficient-length"
	req := AuthorizeRequest{
		ClientID: "spa", RedirectURI: "https://spa.kz/cb", ResponseType: "code",
		State: "st4te", Nonce: "n0nce",
		CodeChallenge: pkcePair(verifier), CodeChallengeMethod: "S256",
	}
	ch, err := p.Challenge(context.Background(), ChallengeRequest{Nonce: req.Nonce, State: req.State})
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	redirect, err := p.CompleteAuthorization(context.Background(), req, ch.ChallengeID, []byte("sig"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	if got := u.Query().Get("state"); got != "st4te" {
		t.Errorf("state = %q, want it echoed back", got)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code in the redirect")
	}

	tokens, err := p.Exchange(context.Background(), TokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: req.RedirectURI, ClientID: "spa", CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tokens.IDToken == "" || tokens.AccessToken == "" {
		t.Fatalf("tokens = %+v", tokens)
	}
	// The nonce must be bound into the id_token: that is the relying party's own
	// replay protection.
	claims, err := p.signer.Verify(tokens.IDToken, time.Now())
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if claims["nonce"] != "n0nce" {
		t.Errorf("nonce = %v, want it bound into the id_token", claims["nonce"])
	}
	if claims["aud"] != "spa" {
		t.Errorf("aud = %v, want the client id", claims["aud"])
	}

	// A code is single-use: a replay must not mint a second token set.
	if _, err := p.Exchange(context.Background(), TokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: req.RedirectURI, ClientID: "spa", CodeVerifier: verifier,
	}); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("replayed code err = %v, want ErrCodeInvalid", err)
	}
}

func TestExchangeChecksEveryBinding(t *testing.T) {
	verifier := "the-verifier"
	newCode := func(t *testing.T, p *Provider) string {
		t.Helper()
		req := AuthorizeRequest{
			ClientID: "spa", RedirectURI: "https://spa.kz/cb", ResponseType: "code",
			CodeChallenge: pkcePair(verifier), CodeChallengeMethod: "S256",
		}
		ch, _ := p.Challenge(context.Background(), ChallengeRequest{})
		redirect, err := p.CompleteAuthorization(context.Background(), req, ch.ChallengeID, []byte("sig"))
		if err != nil {
			t.Fatalf("complete: %v", err)
		}
		u, _ := url.Parse(redirect)
		return u.Query().Get("code")
	}

	for _, tc := range []struct {
		name string
		mut  func(*TokenRequest)
		want error
	}{
		{"wrong verifier", func(r *TokenRequest) { r.CodeVerifier = "wrong" }, ErrPKCEFailed},
		{"wrong redirect", func(r *TokenRequest) { r.RedirectURI = "https://spa.kz/other" }, ErrCodeInvalid},
		{"unknown client", func(r *TokenRequest) { r.ClientID = "nope" }, ErrUnknownClient},
		{"wrong grant", func(r *TokenRequest) { r.GrantType = "password" }, ErrUnsupportedFlow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProviderWithClients(t)
			req := TokenRequest{
				GrantType: "authorization_code", Code: newCode(t, p),
				RedirectURI: "https://spa.kz/cb", ClientID: "spa", CodeVerifier: verifier,
			}
			tc.mut(&req)
			if _, err := p.Exchange(context.Background(), req); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestExchangeAuthenticatesConfidentialClient keeps a registered secret meaningful.
func TestExchangeAuthenticatesConfidentialClient(t *testing.T) {
	p := newTestProviderWithClients(t)
	req := AuthorizeRequest{
		ClientID: "web", RedirectURI: "https://app.kz/callback", ResponseType: "code",
	}
	ch, _ := p.Challenge(context.Background(), ChallengeRequest{})
	redirect, err := p.CompleteAuthorization(context.Background(), req, ch.ChallengeID, []byte("sig"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	u, _ := url.Parse(redirect)
	code := u.Query().Get("code")

	if _, err := p.Exchange(context.Background(), TokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: req.RedirectURI, ClientID: "web", ClientSecret: "wrong",
	}); !errors.Is(err, ErrClientAuth) {
		t.Fatalf("err = %v, want ErrClientAuth", err)
	}
}

func TestDiscoveryAdvertisesTheBrowserFlow(t *testing.T) {
	p := newTestProviderWithClients(t)
	d := p.Discovery()
	if d.AuthorizationEndpoint == "" || !strings.HasSuffix(d.TokenEndpoint, "/oidc/token") {
		t.Errorf("discovery = %+v", d)
	}
	if !contains(d.GrantTypesSupported, "authorization_code") || !contains(d.ResponseTypesSupported, "code") {
		t.Errorf("grant/response types = %v / %v", d.GrantTypesSupported, d.ResponseTypesSupported)
	}
	if !contains(d.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("PKCE methods = %v", d.CodeChallengeMethodsSupported)
	}
	// The API grant must stay discoverable alongside the standard one.
	if d.ChallengeEndpoint == "" || d.VerifyEndpoint == "" {
		t.Errorf("api grant endpoints missing: %+v", d)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// newTestProviderWithClients builds a provider whose verifier accepts any
// signature, with one public and one confidential client registered.
func newTestProviderWithClients(t *testing.T) *Provider {
	t.Helper()
	clients, err := ParseClients([]string{
		"web|s3cret|https://app.kz/callback",
		"spa||https://spa.kz/cb",
	})
	if err != nil {
		t.Fatalf("clients: %v", err)
	}
	signer, err := LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return New(acceptingVerifier{}, signer, NewMemStore(), Config{
		Issuer: "https://id.example", ChallengeTTL: time.Minute, TokenTTL: time.Hour,
	}, WithClients(clients))
}

// acceptingVerifier stands in for the domain: any signature verifies, with a
// fixed identity.
type acceptingVerifier struct{}

func (acceptingVerifier) Verify(context.Context, core.VerifyInput) (core.VerifyOutput, error) {
	return core.VerifyOutput{Valid: true, Signers: []core.Signer{{
		Valid:       true,
		Certificate: core.Certificate{Subject: core.Subject{CommonName: "ТЕСТОВ ТЕСТ", IIN: "123456789011"}},
		Claims:      &core.Claims{Sub: "123456789011", Name: "ТЕСТОВ ТЕСТ", IIN: "123456789011"},
	}}}, nil
}

func (acceptingVerifier) Validate(context.Context, core.ValidateInput) (core.ValidateOutput, error) {
	return core.ValidateOutput{}, nil
}
