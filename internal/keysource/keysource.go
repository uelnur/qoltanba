// Package keysource implements the core.KeySource port: it turns a request's
// KeySpec into concrete key material the Kalkan driver can load. It is
// infrastructure — the domain declares the interface, this package backs it.
//
// Scope (synchronous core): inline PKCS#12, a path on the server, and hardware
// tokens. keyId (a configured keystore) is recognized but returns
// ErrUnsupported until the keystore lands. Secrets (passwords, PINs) are handled
// as ephemerally as the driver allows and never logged by this package.
package keysource

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
)

// ErrInlineDisabled is returned when an inline key arrives on a transport that
// has not been marked safe for secrets in the body (non-TLS, non-local).
var ErrInlineDisabled = errors.New("keysource: inline keys are disabled on this transport")

// ErrUnsupported is returned for key variants not available in this build
// (currently keyId without a configured keystore).
var ErrUnsupported = errors.New("keysource: key variant not supported")

// Resolver dispatches a KeySpec to the right resolution strategy.
type Resolver struct {
	// AllowInline permits PKCS#12 material in the request body. It must be false
	// on transports where the body is not confidential (see the secrets rule); a
	// transport that is TLS/local enables it per call via AllowInlineForCall.
	allowInline bool
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithInline enables or disables inline keys at construction time (the default
// policy; a transport may still gate per call).
func WithInline(allow bool) Option { return func(r *Resolver) { r.allowInline = allow } }

// New builds a Resolver.
func New(opts ...Option) *Resolver {
	r := &Resolver{}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve implements core.KeySource.
func (r *Resolver) Resolve(_ context.Context, spec core.KeySpec) (core.KeyHandle, error) {
	switch {
	case spec.Inline != nil:
		return r.resolveInline(spec.Inline)
	case spec.Path != nil:
		return resolvePath(spec.Path)
	case spec.Token != nil:
		return resolveToken(spec.Token)
	case spec.KeyID != "":
		return core.KeyHandle{}, ErrUnsupported
	default:
		return core.KeyHandle{}, errors.New("keysource: empty key spec")
	}
}

// resolveInline materializes PKCS#12 bytes into a private temp file the driver
// loads by path, cleaning it up on Release.
func (r *Resolver) resolveInline(k *core.InlineKey) (core.KeyHandle, error) {
	if !r.allowInline {
		return core.KeyHandle{}, ErrInlineDisabled
	}
	if len(k.P12) == 0 {
		return core.KeyHandle{}, errors.New("keysource: empty inline p12")
	}
	f, err := os.CreateTemp("", "kalkan-key-*.p12")
	if err != nil {
		return core.KeyHandle{}, fmt.Errorf("keysource: temp key file: %w", err)
	}
	path := f.Name()
	// 0600 before writing secret bytes.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return core.KeyHandle{}, fmt.Errorf("keysource: chmod temp key: %w", err)
	}
	if _, err := f.Write(k.P12); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return core.KeyHandle{}, fmt.Errorf("keysource: write temp key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return core.KeyHandle{}, fmt.Errorf("keysource: close temp key: %w", err)
	}
	return core.KeyHandle{
		Ref:     provider.KeyRef{Storage: provider.StoragePKCS12, Path: path, Password: k.Password},
		Release: func() { _ = os.Remove(path) },
	}, nil
}

// resolvePath references a server-side PKCS#12 file.
func resolvePath(k *core.PathKey) (core.KeyHandle, error) {
	if k.Path == "" {
		return core.KeyHandle{}, errors.New("keysource: empty key path")
	}
	return core.KeyHandle{
		Ref: provider.KeyRef{Storage: provider.StoragePKCS12, Path: k.Path, Password: k.Password},
	}, nil
}

// resolveToken references a hardware token / ID card by storage kind + PIN.
func resolveToken(k *core.TokenKey) (core.KeyHandle, error) {
	st, ok := storageByName(k.Storage)
	if !ok {
		return core.KeyHandle{}, fmt.Errorf("keysource: unknown token storage %q", k.Storage)
	}
	return core.KeyHandle{
		Ref: provider.KeyRef{Storage: st, Password: k.PIN},
	}, nil
}

// storageByName maps a storage label to a provider.StorageType.
func storageByName(name string) (provider.StorageType, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "pkcs12", "p12":
		return provider.StoragePKCS12, true
	case "kzidcard", "idcard":
		return provider.StorageKZIDCard, true
	case "kaztoken":
		return provider.StorageKaztoken, true
	case "etoken72k", "etoken":
		return provider.StorageEToken72K, true
	case "jacarta":
		return provider.StorageJaCarta, true
	case "akey", "aquarius":
		return provider.StorageAKey, true
	case "etoken5110":
		return provider.StorageEToken5110, true
	default:
		return 0, false
	}
}
