package core

import (
	"context"

	"github.com/uelnur/qoltanba/internal/provider"
)

// KeySpec is a request-level reference to signing key material. It is a tagged
// union: exactly one variant is populated. The domain hands it to a KeySource,
// which resolves it into a provider.KeyRef for the duration of one operation.
// New variants (keyId, token, builtin) extend this without changing operations.
type KeySpec struct {
	Inline *InlineKey `json:"inline,omitempty"`
	Path   *PathKey   `json:"path,omitempty"`
	Token  *TokenKey  `json:"token,omitempty"`
	KeyID  string     `json:"keyId,omitempty"` // reference into a configured keystore
}

// Empty reports whether no key was specified (valid for verify-only operations).
func (k KeySpec) Empty() bool {
	return k.Inline == nil && k.Path == nil && k.Token == nil && k.KeyID == ""
}

// InlineKey carries PKCS#12 material in the request. Password is a secret: it is
// only accepted over TLS/local sockets and never logged or echoed.
type InlineKey struct {
	P12      []byte `json:"p12"`
	Password string `json:"password"`
	Alias    string `json:"alias,omitempty"`
}

// PathKey references a PKCS#12 file on the server; the password comes from a
// secret/env, not the request body.
type PathKey struct {
	Path     string `json:"path"`
	Password string `json:"password,omitempty"`
	Alias    string `json:"alias,omitempty"`
}

// TokenKey references a hardware token or ID card. PIN is a secret.
type TokenKey struct {
	Storage string `json:"storage"` // e.g. "kaztoken", "kzidcard"
	PIN     string `json:"pin"`
	Alias   string `json:"alias,omitempty"`
}

// KeySource resolves a request's KeySpec into concrete key material the driver
// can load. The domain declares this port; infrastructure implements it
// (inline, path, keyId, token, builtin keystore). Resolve must not leak secrets
// and should return a redactable KeyHandle. Release frees anything Resolve
// acquired (temp files, decrypted buffers).
type KeySource interface {
	Resolve(ctx context.Context, spec KeySpec) (KeyHandle, error)
}

// KeyHandle is a resolved, ready-to-load key. Ref is passed to the Provider;
// Release is called once the operation completes.
type KeyHandle struct {
	Ref     provider.KeyRef
	Release func()
}

// release runs the handle's cleanup if present.
func (h KeyHandle) release() {
	if h.Release != nil {
		h.Release()
	}
}

// TrustStore supplies the CA certificates used to build and anchor chains during
// verification and validation. The domain declares the port; infrastructure
// backs it with the RK CA registry (internal/pki) plus consumer-supplied CAs.
type TrustStore interface {
	// Anchors returns the configured trusted CA certificates (roots and
	// intermediates) to load before a chain operation.
	Anchors() []TrustedCert
}
