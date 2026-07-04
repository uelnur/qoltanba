package core

import (
	"context"

	"github.com/uelnur/qoltanba/internal/provider"
)

// fakeProvider is a configurable Provider stand-in for domain tests: no cgo, no
// Kalkan. Each method returns the configured result/error and records the last
// request so tests can assert the mapping.
type fakeProvider struct {
	caps provider.Capabilities

	signResult   provider.SignResult
	signErr      error
	lastSignCMS  *provider.SignRequest
	lastSignXML  *provider.SignXMLRequest
	lastSignWSSE *provider.SignWSSERequest

	verifyResult provider.VerifyResult
	verifyErr    error
	lastVerify   *provider.VerifyRequest

	// props keyed by cert bytes (as string); default returned when absent.
	props       provider.CertProperties
	propsErr    error
	lastCertReq []byte

	exportResult provider.ExportResult
	exportErr    error

	validateResult provider.ValidateResult
	validateErr    error
	lastValidate   *provider.ValidateRequest
}

func (f *fakeProvider) Capabilities() provider.Capabilities { return f.caps }

func (f *fakeProvider) SignCMS(_ context.Context, req provider.SignRequest) (provider.SignResult, error) {
	r := req
	f.lastSignCMS = &r
	return f.signResult, f.signErr
}

func (f *fakeProvider) SignXML(_ context.Context, req provider.SignXMLRequest) (provider.SignResult, error) {
	r := req
	f.lastSignXML = &r
	return f.signResult, f.signErr
}

func (f *fakeProvider) SignWSSE(_ context.Context, req provider.SignWSSERequest) (provider.SignResult, error) {
	r := req
	f.lastSignWSSE = &r
	return f.signResult, f.signErr
}

func (f *fakeProvider) VerifyCMS(_ context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	r := req
	f.lastVerify = &r
	return f.verifyResult, f.verifyErr
}

func (f *fakeProvider) VerifyXML(_ context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	r := req
	f.lastVerify = &r
	return f.verifyResult, f.verifyErr
}

func (f *fakeProvider) ExportOwnerCert(_ context.Context, _ provider.KeyRef, _ provider.CertFormat) (provider.ExportResult, error) {
	return f.exportResult, f.exportErr
}

func (f *fakeProvider) Hash(_ context.Context, _ provider.HashRequest) (provider.HashResult, error) {
	return provider.HashResult{}, provider.ErrUnsupported
}

func (f *fakeProvider) SignHash(_ context.Context, _ provider.SignHashRequest) (provider.SignResult, error) {
	return provider.SignResult{}, provider.ErrUnsupported
}

func (f *fakeProvider) CertProperties(_ context.Context, cert []byte, _ provider.CertFormat) (provider.CertProperties, error) {
	f.lastCertReq = cert
	return f.props, f.propsErr
}

func (f *fakeProvider) ValidateCert(_ context.Context, req provider.ValidateRequest) (provider.ValidateResult, error) {
	r := req
	f.lastValidate = &r
	return f.validateResult, f.validateErr
}

func (f *fakeProvider) Close() error { return nil }

// staticKeySource resolves any spec to a fixed KeyRef.
type staticKeySource struct{ ref provider.KeyRef }

func (s staticKeySource) Resolve(_ context.Context, _ KeySpec) (KeyHandle, error) {
	return KeyHandle{Ref: s.ref}, nil
}

// fields builds a CertProperties from name→value pairs, marking each present.
func fields(kv map[string]string) provider.CertProperties {
	var p provider.CertProperties
	for name, val := range kv {
		p.Fields = append(p.Fields, provider.CertField{Name: name, Value: val, OK: true})
	}
	return p
}
