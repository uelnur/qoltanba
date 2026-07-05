package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// b64 is the JOSE base64url encoding (no padding) used for all JWT segments and
// JWK components.
var b64 = base64.RawURLEncoding

// Signer mints and verifies the service's own JWTs (id_token / access_token)
// with a local RSA key using RS256. This is deliberately independent of the
// user's ЭЦП: the user signs the challenge with a GOST key via Kalkan (verified
// by the domain), while the tokens issued to a relying party are RS256-signed and
// published through JWKS so any standard OIDC client can verify them.
//
// It hand-rolls a minimal JWS on the standard library rather than pulling a JOSE
// dependency — the project already hand-rolls ASN.1 in internal/cms.
type Signer struct {
	key *rsa.PrivateKey
	kid string
	// Ephemeral is true when the key was generated in memory (no key path): the
	// JWKS key id then changes on every restart, invalidating live tokens.
	Ephemeral bool
}

// LoadOrGenerate returns a Signer backed by an RSA-2048 key. With an empty path
// the key is generated in memory (Ephemeral). With a path, the key is loaded from
// that PEM file when it exists, or generated and written there 0600 on first
// start — giving a stable kid across restarts.
func LoadOrGenerate(path string) (*Signer, error) {
	if strings.TrimSpace(path) == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return newSigner(key, true)
	}
	switch data, err := os.ReadFile(path); {
	case err == nil:
		key, perr := parsePrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("oidc: parse key %s: %w", path, perr)
		}
		return newSigner(key, false)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("oidc: read key %s: %w", path, err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, fmt.Errorf("oidc: write key %s: %w", path, err)
	}
	return newSigner(key, false)
}

func newSigner(key *rsa.PrivateKey, ephemeral bool) (*Signer, error) {
	kid, err := thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, kid: kid, Ephemeral: ephemeral}, nil
}

// KeyID returns the JWKS key id (kid) of the active signing key.
func (s *Signer) KeyID() string { return s.kid }

// Sign builds a compact RS256 JWS over the JSON-encoded claims.
func (s *Signer) Sign(claims any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// Verify checks a compact RS256 JWS produced by this signer and returns its
// claims, enforcing the exp bound against now.
func (s *Signer) Verify(token string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return nil, ErrTokenInvalid
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenInvalid
	}
	if exp, ok := claims["exp"].(float64); ok && now.After(time.Unix(int64(exp), 0)) {
		return nil, ErrTokenExpired
	}
	return claims, nil
}

// JWKS returns the public JSON Web Key Set advertising the signing key.
func (s *Signer) JWKS() JWKSet {
	pub := s.key.PublicKey
	return JWKSet{Keys: []JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: s.kid,
		N:   b64.EncodeToString(pub.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// thumbprint is the JWKS key id: base64url(SHA-256(DER SubjectPublicKeyInfo)).
func thumbprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return b64.EncodeToString(sum[:]), nil
}

// parsePrivateKey reads a PEM RSA private key in PKCS#1 or PKCS#8 form.
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return key, nil
}
