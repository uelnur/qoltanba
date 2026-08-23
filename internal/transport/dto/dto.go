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
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// SignRequest is the wire shape of a sign call.
type SignRequest struct {
	Policy            string       `json:"policy,omitempty"` // ETSI profile: cades-b|cades-t|xades-b|xades-t
	Format            string       `json:"format"`
	Data              []byte       `json:"data"`
	DataPath          string       `json:"dataPath,omitempty"` // by-reference: local file path (gated)
	DataURL           string       `json:"dataUrl,omitempty"`  // by-reference: URL streamed to spool (gated)
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
	// A named policy supplies the format, so an empty format is valid then; the
	// domain rejects a policy that contradicts an explicit one.
	var f core.SignatureFormat
	if r.Format != "" || r.Policy == "" {
		parsed, err := parseFormat(r.Format)
		if err != nil {
			return core.SignInput{}, err
		}
		f = parsed
	}
	return core.SignInput{
		Policy:            core.SignaturePolicy(r.Policy),
		Format:            f,
		Data:              r.Data,
		DataRef:           core.DataRef{Path: r.DataPath, URL: r.DataURL},
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
	DataPath       string             `json:"dataPath,omitempty"` // by-reference detached source: local path (gated)
	DataURL        string             `json:"dataUrl,omitempty"`  // by-reference detached source: URL (gated)
	Detached       bool               `json:"detached,omitempty"`
	InputPEM       bool               `json:"inputPem,omitempty"`
	CheckCertTime  bool               `json:"checkCertTime,omitempty"`
	ExtractContent bool               `json:"extractContent,omitempty"`
	Claims         bool               `json:"claims,omitempty"`  // add OIDC claims per signer
	Explain        bool               `json:"explain,omitempty"` // add a "why (in)valid" diagnosis
	Report         bool               `json:"report,omitempty"`  // add the human-facing verification card
	Receipt        bool               `json:"receipt,omitempty"` // add the service-signed attestation of the outcome
	TrustedCerts   []core.TrustedCert `json:"trustedCerts,omitempty"`
	// RevocationCheck is a pointer so an absent field means the default (on)
	// rather than false — omitting it must not silently disable the check.
	RevocationCheck  *bool  `json:"revocationCheck,omitempty"`
	RevocationMethod string `json:"revocationMethod,omitempty"` // ocsp|crl (default ocsp)
	ResponderURL     string `json:"responderUrl,omitempty"`     // override the OCSP responder
	Archive          bool   `json:"archive,omitempty"`          // embed this verification's evidence (CAdES-LT)
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
		DataRef:        core.DataRef{Path: r.DataPath, URL: r.DataURL},
		Detached:       r.Detached,
		InputPEM:       r.InputPEM,
		CheckCertTime:  r.CheckCertTime,
		ExtractContent: r.ExtractContent,
		ExtractClaims:  r.Claims,
		Explain:        r.Explain,
		Report:         r.Report,
		Receipt:        r.Receipt,
		TrustedCerts:   r.TrustedCerts,

		RevocationCheck:  r.RevocationCheck,
		RevocationMethod: core.ValidationMethod(r.RevocationMethod),
		ResponderURL:     r.ResponderURL,
		Archive:          r.Archive,
	}, nil
}

// RegistryItemRequest is one document in a registry request: a normal verify plus
// an optional caller label echoed back in the register row, so the register maps
// onto the caller's own inventory (file name, document id).
type RegistryItemRequest struct {
	Ref string `json:"ref,omitempty"`
	VerifyRequest
}

// RegistryItemToCore maps a registry item to its domain form.
func RegistryItemToCore(r RegistryItemRequest) (core.RegistryItem, error) {
	in, err := r.ToCore()
	if err != nil {
		return core.RegistryItem{}, err
	}
	return core.RegistryItem{Ref: r.Ref, Verify: in}, nil
}

// ArchiveRequest asks for long-term validation evidence to be embedded into a
// signature, so it stays verifiable after its certificate expires and the CA's
// responders go away.
type ArchiveRequest struct {
	Signature    []byte             `json:"signature"`
	InputPEM     bool               `json:"inputPem,omitempty"`
	Data         []byte             `json:"data,omitempty"`
	Detached     bool               `json:"detached,omitempty"`
	ResponderURL string             `json:"responderUrl,omitempty"`
	OutputPEM    bool               `json:"outputPem,omitempty"`
	TrustedCerts []core.TrustedCert `json:"trustedCerts,omitempty"`
	// AllowRevoked archives a signature whose signer is revoked. Off by default:
	// reporting "archived" for a repudiated signature files evidence of the wrong
	// thing.
	AllowRevoked bool `json:"allowRevoked,omitempty"`
}

// ToCore converts to the domain input.
func (r ArchiveRequest) ToCore() core.ArchiveInput {
	return core.ArchiveInput{
		Signature: r.Signature, InputPEM: r.InputPEM, Data: r.Data, Detached: r.Detached,
		ResponderURL: r.ResponderURL, OutputPEM: r.OutputPEM, TrustedCerts: r.TrustedCerts,
		AllowRevoked: r.AllowRevoked,
	}
}

// VerifyAtRequest is the wire shape of a point-in-time (historical) verify call:
// a standard verify plus the instant to evaluate validity at and the revocation
// source used to reconstruct past status.
type VerifyAtRequest struct {
	VerifyRequest
	At           time.Time `json:"at"`               // required: the past instant (RFC3339)
	Method       string    `json:"method,omitempty"` // ocsp|crl (default ocsp)
	CRL          []byte    `json:"crl,omitempty"`    // inline archived CRL for method=crl
	ResponderURL string    `json:"responderUrl,omitempty"`
}

// ToCore converts to the domain input.
func (r VerifyAtRequest) ToCore() (core.VerifyAtInput, error) {
	base, err := r.VerifyRequest.ToCore()
	if err != nil {
		return core.VerifyAtInput{}, err
	}
	return core.VerifyAtInput{
		VerifyInput:  base,
		At:           r.At,
		Method:       parseMethod(r.Method),
		CRL:          r.CRL,
		ResponderURL: r.ResponderURL,
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
	Claims       bool               `json:"claims,omitempty"` // add OIDC claims from the certificate
	Method       string             `json:"method,omitempty"` // ocsp|crl
	TrustedCerts []core.TrustedCert `json:"trustedCerts,omitempty"`
}

// ToCore converts to the domain input.
func (r CertInfoRequest) ToCore() core.CertInfoInput {
	return core.CertInfoInput{
		Cert:          r.Cert,
		Key:           r.Key,
		Format:        parseEncoding(r.Encoding),
		BuildChain:    r.BuildChain,
		Validate:      r.Validate,
		ExtractClaims: r.Claims,
		Method:        parseMethod(r.Method),
		TrustedCerts:  r.TrustedCerts,
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
