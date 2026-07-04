// Package dto is the shared wire contract for the thin transports (REST, CLI):
// JSON request shapes and their mapping to the domain's core inputs. Keeping it
// in one place makes every transport speak the same contract by construction.
//
// Binary fields are []byte, which Go's encoding/json renders as base64 strings
// on the wire — matching the data-contract (binary as base64, times as RFC3339).
// Responses are the core output types directly (they already carry json tags).
package dto

import (
	"fmt"

	"github.com/uelnur/qoltanba/internal/core"
)

// SignRequest is the wire shape of a sign call.
type SignRequest struct {
	Format            string       `json:"format"`
	Data              []byte       `json:"data"`
	Key               core.KeySpec `json:"key"`
	Detached          bool         `json:"detached,omitempty"`
	WithTimestamp     *bool        `json:"withTimestamp,omitempty"` // omitted → service default
	TSAURL            string       `json:"tsaUrl,omitempty"`
	NoCheckCertTime   bool         `json:"noCheckCertTime,omitempty"`
	InputPEM          bool         `json:"inputPem,omitempty"`
	OutputPEM         bool         `json:"outputPem,omitempty"`
	NodeID            string       `json:"nodeId,omitempty"`
	ParentNode        string       `json:"parentNode,omitempty"`
	ParentNamespace   string       `json:"parentNamespace,omitempty"`
	ExistingSignature []byte       `json:"existingSignature,omitempty"`
}

// ToCore converts to the domain input, validating the format.
func (r SignRequest) ToCore() (core.SignInput, error) {
	f, err := parseFormat(r.Format)
	if err != nil {
		return core.SignInput{}, err
	}
	return core.SignInput{
		Format:            f,
		Data:              r.Data,
		Key:               r.Key,
		Detached:          r.Detached,
		WithTimestamp:     r.WithTimestamp,
		TSAURL:            r.TSAURL,
		NoCheckCertTime:   r.NoCheckCertTime,
		InputPEM:          r.InputPEM,
		OutputPEM:         r.OutputPEM,
		NodeID:            r.NodeID,
		ParentNode:        r.ParentNode,
		ParentNS:          r.ParentNamespace,
		ExistingSignature: r.ExistingSignature,
	}, nil
}

// VerifyRequest is the wire shape of a verify call.
type VerifyRequest struct {
	Format         string             `json:"format"`
	Signature      []byte             `json:"signature"`
	Data           []byte             `json:"data,omitempty"`
	Detached       bool               `json:"detached,omitempty"`
	InputPEM       bool               `json:"inputPem,omitempty"`
	CheckCertTime  bool               `json:"checkCertTime,omitempty"`
	ExtractContent bool               `json:"extractContent,omitempty"`
	TrustedCerts   []core.TrustedCert `json:"trustedCerts,omitempty"`
}

// ToCore converts to the domain input.
func (r VerifyRequest) ToCore() (core.VerifyInput, error) {
	f, err := parseFormat(r.Format)
	if err != nil {
		return core.VerifyInput{}, err
	}
	return core.VerifyInput{
		Format:         f,
		Signature:      r.Signature,
		Data:           r.Data,
		Detached:       r.Detached,
		InputPEM:       r.InputPEM,
		CheckCertTime:  r.CheckCertTime,
		ExtractContent: r.ExtractContent,
		TrustedCerts:   r.TrustedCerts,
	}, nil
}

// ExtractRequest is the wire shape of an extract call.
type ExtractRequest struct {
	Format    string `json:"format"`
	Signature []byte `json:"signature"`
	Data      []byte `json:"data,omitempty"`
}

// ToCore converts to the domain input.
func (r ExtractRequest) ToCore() (core.ExtractInput, error) {
	f, err := parseFormat(r.Format)
	if err != nil {
		return core.ExtractInput{}, err
	}
	return core.ExtractInput{Format: f, Signature: r.Signature, Data: r.Data}, nil
}

// CertInfoRequest is the wire shape of a certificate-info call.
type CertInfoRequest struct {
	Cert         []byte             `json:"cert,omitempty"`
	Key          core.KeySpec       `json:"key,omitempty"`
	Encoding     string             `json:"encoding,omitempty"` // pem|der|base64
	BuildChain   bool               `json:"buildChain,omitempty"`
	Validate     bool               `json:"validate,omitempty"`
	Method       string             `json:"method,omitempty"` // ocsp|crl
	TrustedCerts []core.TrustedCert `json:"trustedCerts,omitempty"`
}

// ToCore converts to the domain input.
func (r CertInfoRequest) ToCore() core.CertInfoInput {
	return core.CertInfoInput{
		Cert:         r.Cert,
		Key:          r.Key,
		Format:       parseEncoding(r.Encoding),
		BuildChain:   r.BuildChain,
		Validate:     r.Validate,
		Method:       parseMethod(r.Method),
		TrustedCerts: r.TrustedCerts,
	}
}

// ValidateRequest is the wire shape of a certificate-validate call.
type ValidateRequest struct {
	Cert         []byte             `json:"cert"`
	Encoding     string             `json:"encoding,omitempty"`
	Method       string             `json:"method,omitempty"`
	WantOCSP     bool               `json:"wantOcsp,omitempty"`
	ResponderURL string             `json:"responderUrl,omitempty"`
	CRL          []byte             `json:"crl,omitempty"`
	TrustedCerts []core.TrustedCert `json:"trustedCerts,omitempty"`
}

// ToCore converts to the domain input.
func (r ValidateRequest) ToCore() core.ValidateInput {
	return core.ValidateInput{
		Cert:         r.Cert,
		Format:       parseEncoding(r.Encoding),
		Method:       parseMethod(r.Method),
		WantOCSP:     r.WantOCSP,
		ResponderURL: r.ResponderURL,
		CRL:          r.CRL,
		TrustedCerts: r.TrustedCerts,
	}
}

func parseFormat(s string) (core.SignatureFormat, error) {
	f := core.SignatureFormat(s)
	if !f.Valid() {
		return "", fmt.Errorf("unknown signature format %q (want cms|xml|wsse)", s)
	}
	return f, nil
}

func parseEncoding(s string) core.CertEncoding {
	switch s {
	case "der":
		return core.EncodingDER
	case "base64":
		return core.EncodingB64
	default:
		return core.EncodingPEM
	}
}

func parseMethod(s string) core.ValidationMethod {
	if s == "crl" {
		return core.MethodCRL
	}
	return core.MethodOCSP
}
