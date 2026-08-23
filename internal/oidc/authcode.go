package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// The authorization-code flow exists so an off-the-shelf OIDC client (Laravel
// Socialite, a Spring or .NET library) works without a custom driver: it
// redirects the browser to /oidc/authorize, the user signs a challenge there, and
// the browser comes back to the client with a code that /oidc/token exchanges for
// tokens. The API flow (/oidc/challenge + /oidc/verify) stays as it is for
// callers that drive the handshake themselves.

// Authorization-code lifetime and size. Codes are short-lived by design: they
// travel through a browser redirect, where they can be logged, and their only job
// is to survive one immediate round trip.
const (
	authCodeTTL = 60 * time.Second
)

// Client is a registered relying party. Only registered redirect URIs are ever
// redirected to — that check is what keeps an authorization code from being
// handed to an attacker's site.
type Client struct {
	ID string
	// Secret authenticates a confidential client at the token endpoint. Empty
	// makes the client public, and public clients must use PKCE.
	Secret       string
	RedirectURIs []string
}

// redirectAllowed reports whether uri is registered. Comparison is exact: partial
// or prefix matching is how open redirects happen.
func (c Client) redirectAllowed(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// Clients is the registry of relying parties.
type Clients map[string]Client

// ParseClients reads the configured entries, each "client_id|secret|redirect_uri
// [|redirect_uri...]". A public client (empty secret) is written with an empty
// middle field, which keeps one format for both kinds instead of two shapes to
// tell apart.
func ParseClients(entries []string) (Clients, error) {
	out := make(Clients, len(entries))
	for _, raw := range entries {
		parts := strings.Split(raw, "|")
		if len(parts) < 3 {
			return nil, fmt.Errorf("client %q: want client_id|secret|redirect_uri[|redirect_uri...]", raw)
		}
		id := strings.TrimSpace(parts[0])
		if id == "" {
			return nil, fmt.Errorf("client %q: empty client_id", raw)
		}
		var uris []string
		for _, u := range parts[2:] {
			if u = strings.TrimSpace(u); u != "" {
				uris = append(uris, u)
			}
		}
		if len(uris) == 0 {
			return nil, fmt.Errorf("client %q: no redirect_uri", id)
		}
		out[id] = Client{ID: id, Secret: strings.TrimSpace(parts[1]), RedirectURIs: uris}
	}
	return out, nil
}

// AuthorizeRequest is the browser-facing authorization request.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// Flow errors specific to the authorization-code leg.
var (
	ErrUnknownClient    = errors.New("unknown client")
	ErrRedirectMismatch = errors.New("redirect_uri is not registered for this client")
	ErrUnsupportedFlow  = errors.New("unsupported response_type")
	ErrPKCERequired     = errors.New("code_challenge with S256 is required")
	ErrPKCEFailed       = errors.New("code_verifier does not match the challenge")
	ErrCodeInvalid      = errors.New("authorization code is unknown, used or expired")
	ErrClientAuth       = errors.New("client authentication failed")
)

// authCode is an issued authorization code awaiting exchange.
type authCode struct {
	clientID      string
	redirectURI   string
	nonce         string
	claims        core.Claims
	codeChallenge string
	expiresAt     time.Time
}

// codeStore holds authorization codes. It is in-memory and node-local on purpose:
// a code lives for seconds and is consumed by the client that just received the
// redirect, so surviving a restart buys nothing.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]authCode
}

func newCodeStore() *codeStore { return &codeStore{codes: make(map[string]authCode)} }

func (s *codeStore) put(code string, c authCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = c
}

// take returns the code and removes it: a code is single-use, and consuming it
// atomically is what makes a replay fail.
func (s *codeStore) take(code string, now time.Time) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return authCode{}, false
	}
	delete(s.codes, code)
	if !c.expiresAt.After(now) {
		return authCode{}, false
	}
	return c, true
}

func (s *codeStore) reap(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.codes {
		if !c.expiresAt.After(now) {
			delete(s.codes, k)
		}
	}
}

// ValidateAuthorize checks an authorization request before anything is shown to
// the user. It returns the resolved client so the caller can render the login
// page for it.
//
// The order matters: client and redirect URI are validated first, because every
// later error is reported *to* that redirect URI, and reporting an error to an
// unverified destination is itself the vulnerability.
func (p *Provider) ValidateAuthorize(req AuthorizeRequest) (Client, error) {
	client, ok := p.clients[req.ClientID]
	if !ok {
		return Client{}, ErrUnknownClient
	}
	if req.RedirectURI == "" || !client.redirectAllowed(req.RedirectURI) {
		return Client{}, ErrRedirectMismatch
	}
	if req.ResponseType != "code" {
		return client, ErrUnsupportedFlow
	}
	// PKCE is mandatory for public clients and accepted (recommended) for
	// confidential ones: the code travels through a browser either way.
	if client.Secret == "" {
		if req.CodeChallenge == "" || !strings.EqualFold(req.CodeChallengeMethod, "S256") {
			return client, ErrPKCERequired
		}
	}
	if req.CodeChallenge != "" && !strings.EqualFold(req.CodeChallengeMethod, "S256") {
		// Plain PKCE offers no protection over no PKCE at all; refusing it is
		// better than pretending the request is protected.
		return client, ErrPKCERequired
	}
	return client, nil
}

// CompleteAuthorization consumes the signed challenge, derives the user's identity
// and issues an authorization code bound to this client, redirect URI and PKCE
// challenge. It returns the redirect URL the browser should be sent to.
func (p *Provider) CompleteAuthorization(ctx context.Context, req AuthorizeRequest, challengeID string, signature []byte) (string, error) {
	client, err := p.ValidateAuthorize(req)
	if err != nil {
		return "", err
	}
	claims, err := p.VerifySignature(ctx, challengeID, signature)
	if err != nil {
		return "", err
	}

	code, err := randID()
	if err != nil {
		return "", err
	}
	p.codes.put(code, authCode{
		clientID:      client.ID,
		redirectURI:   req.RedirectURI,
		nonce:         req.Nonce,
		claims:        claims,
		codeChallenge: req.CodeChallenge,
		expiresAt:     p.now().Add(authCodeTTL),
	})

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", ErrRedirectMismatch
	}
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenRequest is the authorization-code exchange at the token endpoint.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
}

// Exchange trades an authorization code for tokens. Every binding recorded when
// the code was issued is re-checked here: a code is only valid for the client,
// the redirect URI and the PKCE verifier it was issued against.
func (p *Provider) Exchange(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	if req.GrantType != "authorization_code" {
		return TokenResponse{}, fmt.Errorf("%w: %q", ErrUnsupportedFlow, req.GrantType)
	}
	client, ok := p.clients[req.ClientID]
	if !ok {
		return TokenResponse{}, ErrUnknownClient
	}
	if client.Secret != "" && subtle.ConstantTimeCompare([]byte(client.Secret), []byte(req.ClientSecret)) != 1 {
		return TokenResponse{}, ErrClientAuth
	}

	code, ok := p.codes.take(req.Code, p.now())
	if !ok {
		return TokenResponse{}, ErrCodeInvalid
	}
	if code.clientID != req.ClientID || code.redirectURI != req.RedirectURI {
		return TokenResponse{}, ErrCodeInvalid
	}
	if code.codeChallenge != "" && !verifyPKCE(code.codeChallenge, req.CodeVerifier) {
		return TokenResponse{}, ErrPKCEFailed
	}
	return p.IssueTokens(ctx, code.claims, req.ClientID, code.nonce)
}

// verifyPKCE checks an S256 code verifier against the stored challenge.
func verifyPKCE(challenge, verifier string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(want)) == 1
}
