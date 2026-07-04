package core

import (
	"context"
	"errors"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Service is the transport-independent domain facade. It orchestrates one
// operation at a time: resolve the key, call the Provider, assemble the
// exhaustive best-effort result. Every transport maps its wire format to these
// methods; none of them contains crypto or driver logic.
type Service struct {
	prov             provider.Provider
	keys             KeySource
	trust            TrustStore
	fetcher          IssuerFetcher
	crl              CRLSource
	verifyChain      bool
	defaultTimestamp bool
	now              func() time.Time
	verifyOnly       bool
}

// Option configures a Service.
type Option func(*Service)

// WithKeySource sets the key resolver. Required unless the service runs
// verify-only.
func WithKeySource(k KeySource) Option { return func(s *Service) { s.keys = k } }

// WithTrustStore sets the CA trust store used for chain operations.
func WithTrustStore(t TrustStore) Option { return func(s *Service) { s.trust = t } }

// WithClock injects the time source (tests use a fixed clock).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithVerifyOnly disables the key path and sign operations entirely.
func WithVerifyOnly(v bool) Option { return func(s *Service) { s.verifyOnly = v } }

// WithIssuerFetcher enables AIA issuer download during chain building. Nil (the
// default) means no network fetch — chains build only from the trusted set.
func WithIssuerFetcher(f IssuerFetcher) Option { return func(s *Service) { s.fetcher = f } }

// WithCRLSource enables CRL lookup for revocation checks when the caller did not
// supply a CRL inline. Nil (the default) means a Method=CRL request without inline
// CRL bytes is left to fail at the library, as before.
func WithCRLSource(c CRLSource) Option { return func(s *Service) { s.crl = c } }

// WithDefaultTimestamp sets whether signing adds a TSA timestamp when the
// request does not specify (SignInput.WithTimestamp == nil). Off by default.
func WithDefaultTimestamp(v bool) Option { return func(s *Service) { s.defaultTimestamp = v } }

// WithChainVerification enables cryptographic chain validation via Kalkan
// (KC_USE_NOTHING) per signer — the GOST-capable check Go cannot do. Off by
// default (adds a driver call per signer).
func WithChainVerification(v bool) Option { return func(s *Service) { s.verifyChain = v } }

// New builds a Service over the given Provider.
func New(p provider.Provider, opts ...Option) *Service {
	s := &Service{prov: p, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Capabilities exposes the loaded library's capability map for readiness/status.
func (s *Service) Capabilities() provider.Capabilities { return s.prov.Capabilities() }

// VerifyOnly reports whether the sign path is disabled.
func (s *Service) VerifyOnly() bool { return s.verifyOnly }

// Sign signs Data in the requested format, resolving the key through KeySource.
func (s *Service) Sign(ctx context.Context, in SignInput) (SignOutput, error) {
	const op = "Sign"
	if s.verifyOnly {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("sign disabled in verify-only mode")}
	}
	if !in.Format.Valid() {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("unknown signature format")}
	}
	if in.ExistingSignature != nil && in.Format != FormatCMS {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("co-sign supported for CMS only")}
	}

	handle, err := s.resolveKey(ctx, in.Key)
	if err != nil {
		return SignOutput{}, domainErr(op, err)
	}
	defer handle.release()

	// Tri-state: request value overrides the service default.
	withTS := s.defaultTimestamp
	if in.WithTimestamp != nil {
		withTS = *in.WithTimestamp
	}

	var res provider.SignResult
	switch in.Format {
	case FormatCMS:
		res, err = s.prov.SignCMS(ctx, provider.SignRequest{
			Key:               handle.Ref,
			Data:              in.Data,
			Detached:          in.Detached,
			InputPEM:          in.InputPEM,
			OutPEM:            in.OutputPEM,
			CheckCertTime:     !in.NoCheckCertTime,
			WithTimestamp:     withTS,
			TSAURL:            in.TSAURL,
			ExistingSignature: in.ExistingSignature,
		})
	case FormatXML:
		res, err = s.prov.SignXML(ctx, provider.SignXMLRequest{
			Key:           handle.Ref,
			XML:           in.Data,
			CheckCertTime: !in.NoCheckCertTime,
			WithTimestamp: withTS,
			TSAURL:        in.TSAURL,
			NodeID:        in.NodeID,
			ParentNode:    in.ParentNode,
			ParentNS:      in.ParentNS,
		})
	case FormatWSSE:
		res, err = s.prov.SignWSSE(ctx, provider.SignWSSERequest{
			Key:           handle.Ref,
			XML:           in.Data,
			NodeID:        in.NodeID,
			CheckCertTime: !in.NoCheckCertTime,
			WithTimestamp: withTS,
			TSAURL:        in.TSAURL,
		})
	}
	if err != nil {
		return SignOutput{Format: in.Format, LibError: libErrorFrom(err)}, domainErr(op, err)
	}

	out := SignOutput{Signature: res.Signature, Format: in.Format, CAdESLevel: "BES"}
	if withTS {
		// A successful sign implies the token was embedded (the TSA call is part of
		// signing). Echo the parsed TSP for CMS; XML/WSSE carry the level only.
		out.CAdESLevel = "T"
		if in.Format == FormatCMS {
			if ts := firstTimestamp(res.Signature); ts != nil {
				out.Timestamp = ts
			}
		}
	}
	return out, nil
}

// firstTimestamp parses a signed CMS and returns the first TSP token found, or
// nil (best-effort — used to echo the timestamp in the sign response).
func firstTimestamp(signature []byte) *Timestamp {
	for _, si := range cmsSignersBySerial(FormatCMS, signature) {
		if si.Timestamp != nil {
			return timestampFromCMS(si.Timestamp)
		}
	}
	return nil
}

// Verify checks a signature and extracts signers, content and validity. An
// invalid or absent signature is a business result (Valid=false + LibError), not
// a transport error; only infrastructure faults return an error.
func (s *Service) Verify(ctx context.Context, in VerifyInput) (VerifyOutput, error) {
	const op = "Verify"
	if !in.Format.Valid() {
		return VerifyOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("unknown signature format")}
	}
	var w warnings
	trusted := s.mergedTrusted(in.TrustedCerts)
	req := provider.VerifyRequest{
		Signature:     in.Signature,
		Data:          in.Data,
		Detached:      in.Detached,
		InputPEM:      in.InputPEM,
		OutPEM:        true,
		CheckCertTime: in.CheckCertTime,
		TrustedCerts:  toProviderCerts(trusted),
	}

	var res provider.VerifyResult
	var err error
	if in.Format == FormatCMS {
		res, err = s.prov.VerifyCMS(ctx, req)
	} else {
		res, err = s.prov.VerifyXML(ctx, req)
	}

	out := VerifyOutput{
		Valid:    res.Valid,
		Format:   in.Format,
		Detached: in.Detached,
		Signers:  s.buildSigners(ctx, res, in.Format, in.Signature, trusted, &w),
	}
	if in.ExtractContent {
		out.Content = res.Content
	}
	if in.ExtractClaims {
		for i := range out.Signers {
			c := ClaimsFromCertificate(out.Signers[i].Certificate)
			out.Signers[i].Claims = &c
		}
	}
	out.Warnings = w.list()

	if err != nil {
		if isSoftVerifyFailure(err) {
			out.LibError = libErrorFrom(err)
			return out, nil
		}
		return out, domainErr(op, err)
	}
	return out, nil
}

// Extract recovers the original content from an attached signature.
func (s *Service) Extract(ctx context.Context, in ExtractInput) (ExtractOutput, error) {
	const op = "Extract"
	if !in.Format.Valid() {
		return ExtractOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("unknown signature format")}
	}
	req := provider.VerifyRequest{Signature: in.Signature, Data: in.Data, OutPEM: true}
	var res provider.VerifyResult
	var err error
	if in.Format == FormatCMS {
		res, err = s.prov.VerifyCMS(ctx, req)
	} else {
		res, err = s.prov.VerifyXML(ctx, req)
	}
	out := ExtractOutput{Content: res.Content, Detached: len(res.Content) == 0}
	if err != nil && !isSoftVerifyFailure(err) {
		return out, domainErr(op, err)
	}
	if err != nil {
		out.LibError = libErrorFrom(err)
	}
	return out, nil
}

// CertInfo fully parses a certificate. The certificate comes from in.Cert, or is
// exported from the key store when in.Key is set.
func (s *Service) CertInfo(ctx context.Context, in CertInfoInput) (CertInfoOutput, error) {
	const op = "CertInfo"
	var w warnings

	certBytes := in.Cert
	format := in.Format
	if len(certBytes) == 0 && !in.Key.Empty() {
		handle, err := s.resolveKey(ctx, in.Key)
		if err != nil {
			return CertInfoOutput{}, domainErr(op, err)
		}
		defer handle.release()
		exp, err := s.prov.ExportOwnerCert(ctx, handle.Ref, provider.CertPEM)
		if err != nil {
			return CertInfoOutput{}, domainErr(op, err)
		}
		certBytes, format = exp.Cert, EncodingPEM
	}
	if len(certBytes) == 0 {
		return CertInfoOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("no certificate provided")}
	}

	props, err := s.prov.CertProperties(ctx, certBytes, certFormat(format))
	if err != nil {
		return CertInfoOutput{}, domainErr(op, err)
	}
	cert := parseCertificate(props, toDER(certBytes, format), "", &w)

	out := CertInfoOutput{Certificate: cert, Warnings: w.list()}
	if in.ExtractClaims {
		c := ClaimsFromCertificate(cert)
		out.Claims = &c
	}
	if in.Validate {
		vres, verr := s.Validate(ctx, ValidateInput{
			Cert: certBytes, Format: format, Method: in.Method, TrustedCerts: in.TrustedCerts,
		})
		if verr != nil {
			w.addErr("validation", verr)
		} else if vres.Status.LibError != nil {
			w.add("validation", vres.Status.LibError.Code)
		}
		out.Warnings = w.list()
	}
	return out, nil
}

// Validate checks a certificate's revocation status and chain trust.
func (s *Service) Validate(ctx context.Context, in ValidateInput) (ValidateOutput, error) {
	const op = "Validate"
	method := in.Method
	if method == "" {
		method = MethodOCSP
	}
	checkTime := in.CheckTime
	if checkTime.IsZero() {
		checkTime = s.now()
	}

	// Path: OCSP responder URL, or a temp file for a CRL (Kalkan reads a path).
	// Always fetch the raw OCSP so we can parse its structured fields.
	path := in.ResponderURL
	wantOCSP := in.WantOCSP || method == MethodOCSP
	// CRL bytes: prefer the caller's inline CRL; otherwise pull from the CRL cache
	// (the cert's distribution points) when one is configured.
	crlBytes := in.CRL
	if method == MethodCRL && len(crlBytes) == 0 && s.crl != nil {
		if der, ok := s.crl.CRLFor(ctx, toDER(in.Cert, in.Format)); ok {
			crlBytes = der
		}
	}
	if method == MethodCRL && len(crlBytes) > 0 {
		p, cleanup, werr := writeTempCRL(crlBytes)
		if werr != nil {
			return ValidateOutput{}, domainErr(op, werr)
		}
		defer cleanup()
		path = p
	}

	res, err := s.prov.ValidateCert(ctx, provider.ValidateRequest{
		Cert:         in.Cert,
		Format:       certFormat(in.Format),
		Method:       validationMethod(method),
		Path:         path,
		CheckTime:    checkTime,
		WantOCSP:     wantOCSP,
		TrustedCerts: toProviderCerts(s.mergedTrusted(in.TrustedCerts)),
	})

	checked := checkTime
	status := RevocationStatus{
		Method:    method,
		Revoked:   res.Status == provider.StatusRevoked,
		CheckedAt: &checked,
	}
	// Enrich with structured fields parsed from the response/CRL (best-effort).
	if method == MethodOCSP {
		enrichFromOCSP(&status, res.OCSPResponse, res.Info)
	} else if len(crlBytes) > 0 {
		enrichFromCRL(&status, crlBytes, toDER(in.Cert, in.Format))
	}

	out := ValidateOutput{Status: status, Info: res.Info}
	if in.WantOCSP {
		out.OCSPResponse = res.OCSPResponse
	}
	if err != nil {
		if isSoftVerifyFailure(err) {
			out.Status.LibError = libErrorFrom(err)
			return out, nil
		}
		return out, domainErr(op, err)
	}
	return out, nil
}

// buildSigners turns the driver's signer certificates into structured Signers,
// parsing each certificate's properties (best-effort), building its chain, and —
// for CMS — enriching with per-signer facts parsed from the SignedData
// (signingTime, signature algorithm, RFC 3161 timestamp), matched by serial.
func (s *Service) buildSigners(ctx context.Context, res provider.VerifyResult, format SignatureFormat, signature []byte, trusted []TrustedCert, w *warnings) []Signer {
	if len(res.Signers) == 0 {
		return nil
	}
	bySerial := cmsSignersBySerial(format, signature)

	signers := make([]Signer, 0, len(res.Signers))
	for i, pemCert := range res.Signers {
		leafDER := toDER(pemCert, EncodingPEM)
		var cert Certificate
		props, err := s.prov.CertProperties(ctx, pemCert, provider.CertPEM)
		if err != nil {
			w.addErr("signers[]", err)
			cert = Certificate{PEM: pemCert}
		} else {
			cert = parseCertificate(props, leafDER, "signers[].", w)
		}
		chain, complete, anchored := buildChain(ctx, cert, leafDER, trusted, s.fetcher)
		sig := Signer{
			Certificate:      cert,
			Chain:            chain,
			Valid:            res.Valid,
			VerifyInfo:       res.Info,
			CAdESLevel:       "BES",
			ChainComplete:    complete,
			TrustAnchorFound: anchored,
		}
		if s.verifyChain {
			sig.ChainSignaturesVerified = s.cryptoVerifyChain(ctx, pemCert, chain)
		}
		if si, ok := bySerial[normHex(cert.SerialNumber)]; ok {
			sig.SigningTime = si.SigningTime
			sig.SignatureAlgorithm = sigAlgName(si.SignatureAlgorithmOID)
			if si.Timestamp != nil {
				sig.Timestamp = timestampFromCMS(si.Timestamp)
				sig.CAdESLevel = "T"
			}
		}
		if sig.SignatureAlgorithm == "" {
			sig.SignatureAlgorithm = cert.SignatureAlgorithm
		}
		// Fallback: Kalkan's genTime for the first signer when no CMS token parsed.
		if sig.Timestamp == nil && i == 0 && !res.Timestamp.IsZero() {
			t := res.Timestamp.UTC()
			sig.Timestamp = &Timestamp{GenTime: &t}
			sig.CAdESLevel = "T"
		}
		signers = append(signers, sig)
	}
	return signers
}

// cryptoVerifyChain asks Kalkan to build and cryptographically validate the
// signer's chain against its CA nodes plus the configured anchors, without a
// revocation check (KC_USE_NOTHING). This is the GOST-capable verification Go
// cannot perform. A chain error is not a service failure — it just means the
// signatures did not validate, so the flag stays false.
func (s *Service) cryptoVerifyChain(ctx context.Context, leafPEM []byte, chain []Certificate) bool {
	var trusted []provider.TrustedCert
	// CA nodes of the built chain (everything above the leaf).
	for _, node := range chain[1:] {
		trusted = append(trusted, provider.TrustedCert{Cert: node.PEM, Intermediate: !nodeIsRoot(node.PEM)})
	}
	trusted = append(trusted, toProviderCerts(s.mergedTrusted(nil))...)
	if len(trusted) == 0 {
		return false // nothing to anchor against
	}
	res, err := s.prov.ValidateCert(ctx, provider.ValidateRequest{
		Cert:         leafPEM,
		Format:       provider.CertPEM,
		Method:       provider.ValidateNone,
		TrustedCerts: trusted,
	})
	return err == nil && res.RawCode == 0
}

// resolveKey resolves in through the KeySource, erroring clearly when a key is
// required but no source is configured.
func (s *Service) resolveKey(ctx context.Context, spec KeySpec) (KeyHandle, error) {
	if spec.Empty() {
		return KeyHandle{}, &Error{Kind: KindInvalid, Op: "resolveKey", err: errors.New("no key specified")}
	}
	if s.keys == nil {
		return KeyHandle{}, &Error{Kind: KindUnavailable, Op: "resolveKey", err: errors.New("no key source configured")}
	}
	return s.keys.Resolve(ctx, spec)
}

// mergedTrusted merges the configured trust anchors with per-request CAs.
func (s *Service) mergedTrusted(extra []TrustedCert) []TrustedCert {
	var all []TrustedCert
	if s.trust != nil {
		all = append(all, s.trust.Anchors()...)
	}
	return append(all, extra...)
}

// toProviderCerts adapts domain trusted certs to the driver's type.
func toProviderCerts(in []TrustedCert) []provider.TrustedCert {
	if len(in) == 0 {
		return nil
	}
	out := make([]provider.TrustedCert, len(in))
	for i, c := range in {
		out[i] = provider.TrustedCert{Cert: c.Cert, Intermediate: c.Intermediate}
	}
	return out
}
