// Package fake provides a configurable Provider test double: no cgo, no Kalkan.
// Transports and the domain can be exercised end-to-end against it. Each method
// returns the configured result/error; hooks override behavior when set.
package fake

import (
	"context"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Provider is an in-memory Provider stand-in.
type Provider struct {
	Caps provider.Capabilities

	SignResult provider.SignResult
	SignErr    error

	VerifyResult provider.VerifyResult
	VerifyErr    error

	Props    provider.CertProperties
	PropsErr error

	ExportResult provider.ExportResult
	ExportErr    error

	ValidateResult provider.ValidateResult
	ValidateErr    error
}

func (f *Provider) Capabilities() provider.Capabilities { return f.Caps }

func (f *Provider) SignCMS(context.Context, provider.SignRequest) (provider.SignResult, error) {
	return f.SignResult, f.SignErr
}

func (f *Provider) SignXML(context.Context, provider.SignXMLRequest) (provider.SignResult, error) {
	return f.SignResult, f.SignErr
}

func (f *Provider) SignWSSE(context.Context, provider.SignWSSERequest) (provider.SignResult, error) {
	return f.SignResult, f.SignErr
}

func (f *Provider) VerifyCMS(context.Context, provider.VerifyRequest) (provider.VerifyResult, error) {
	return f.VerifyResult, f.VerifyErr
}

func (f *Provider) VerifyXML(context.Context, provider.VerifyRequest) (provider.VerifyResult, error) {
	return f.VerifyResult, f.VerifyErr
}

func (f *Provider) ExportOwnerCert(context.Context, provider.KeyRef, provider.CertFormat) (provider.ExportResult, error) {
	return f.ExportResult, f.ExportErr
}

func (f *Provider) Hash(context.Context, provider.HashRequest) (provider.HashResult, error) {
	return provider.HashResult{}, provider.ErrUnsupported
}

func (f *Provider) SignHash(context.Context, provider.SignHashRequest) (provider.SignResult, error) {
	return provider.SignResult{}, provider.ErrUnsupported
}

func (f *Provider) CertProperties(context.Context, []byte, provider.CertFormat) (provider.CertProperties, error) {
	return f.Props, f.PropsErr
}

func (f *Provider) ValidateCert(context.Context, provider.ValidateRequest) (provider.ValidateResult, error) {
	return f.ValidateResult, f.ValidateErr
}

func (f *Provider) Close() error { return nil }

// Fields builds a CertProperties from name→value pairs, each marked present.
func Fields(kv map[string]string) provider.CertProperties {
	var p provider.CertProperties
	for name, val := range kv {
		p.Fields = append(p.Fields, provider.CertField{Name: name, Value: val, OK: true})
	}
	return p
}
