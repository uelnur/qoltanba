package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uelnur/qoltanba/internal/cms"
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
	crlFailPolicy    CRLFailPolicy
	verifyChain      bool
	defaultTimestamp bool
	defaultTSAURL    string
	now              func() time.Time
	verifyOnly       bool
	dataResolver     DataResolver
	ocspCache        OCSPCache
	audit            AuditSink
	receiptSigner    ReceiptSigner
	receiptIssuer    string
	tsaPolicies      []string
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

// WithAudit records signing and verification into a tamper-evident journal.
// Nil (the default) records nothing.
func WithAudit(sink AuditSink) Option { return func(s *Service) { s.audit = sink } }

// WithOCSPCache reuses recent revocation answers instead of asking the responder
// again for the same certificate. It also supplies the raw response for stapling.
// Nil (the default) checks every time.
func WithOCSPCache(c OCSPCache) Option { return func(s *Service) { s.ocspCache = c } }

// WithReceiptSigner enables signed verification receipts: the service attests to
// its own verification outcome with issuer as the iss claim. Without it the
// receipt flag simply yields no receipt — the verification itself is unaffected.
func WithReceiptSigner(signer ReceiptSigner, issuer string) Option {
	return func(s *Service) { s.receiptSigner, s.receiptIssuer = signer, issuer }
}

// WithTSAPolicies restricts which TSA policies a timestamp may be issued under
// for it to count as CAdES-T. Empty (the default) enforces nothing: every NUC
// policy chains to the same anchors, so choosing between them is an operator's
// call about acceptable algorithms, not a fact the service can derive.
func WithTSAPolicies(oids []string) Option { return func(s *Service) { s.tsaPolicies = oids } }

// WithIssuerFetcher enables AIA issuer download during chain building. Nil (the
// default) means no network fetch — chains build only from the trusted set.
func WithIssuerFetcher(f IssuerFetcher) Option { return func(s *Service) { s.fetcher = f } }

// WithCRLSource enables CRL lookup for revocation checks when the caller did not
// supply a CRL inline. Nil (the default) means a Method=CRL request without inline
// CRL bytes is left to fail at the library, as before.
func WithCRLSource(c CRLSource) Option { return func(s *Service) { s.crl = c } }

// CRLFailPolicy decides what a Method=CRL check does when the managed CRL layer
// cannot supply a fresh, base↔delta-consistent CRL.
type CRLFailPolicy int

const (
	// CRLFailSoft (default) treats an unreliable CRL as inconclusive: the check
	// falls back to OCSP (authoritative for real-time status) with a warning.
	CRLFailSoft CRLFailPolicy = iota
	// CRLFailHard fails closed: an unreliable CRL makes the validation invalid.
	CRLFailHard
)

// WithCRLFailPolicy sets the behavior when a managed CRL is unavailable, stale or
// base↔delta inconsistent. The default is CRLFailSoft. Applies only to the managed
// CRL layer (WithCRLSource); a caller-supplied inline CRL is used as-is.
func WithCRLFailPolicy(p CRLFailPolicy) Option { return func(s *Service) { s.crlFailPolicy = p } }

// WithDefaultTimestamp sets whether signing adds a TSA timestamp when the
// request does not specify (SignInput.WithTimestamp == nil). Off by default.
func WithDefaultTimestamp(v bool) Option { return func(s *Service) { s.defaultTimestamp = v } }

// WithDefaultTSAURL sets the timestamp authority used when a request names none.
// Empty leaves the library's built-in default, which is the production responder
// and will not stamp a test certificate.
func WithDefaultTSAURL(u string) Option { return func(s *Service) { s.defaultTSAURL = u } }

// WithDataResolver enables by-reference payloads (DataRef path/URL): the resolver
// turns a reference into a local path the driver reads directly (KC_IN_FILE). Nil
// (the default) means only inline data is accepted.
func WithDataResolver(r DataResolver) Option { return func(s *Service) { s.dataResolver = r } }

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
	if err := applyPolicy(&in); err != nil {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: err}
	}
	if !in.Format.Valid() {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("unknown signature format")}
	}
	if in.ExistingSignature != nil && in.Format != FormatCMS {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("co-sign supported for CMS only")}
	}
	if in.DataRef.IsRef() && in.Format != FormatCMS {
		return SignOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("by-reference data supported for CMS only")}
	}

	dataPath, releaseData, err := s.resolveData(ctx, op, in.DataRef)
	if err != nil {
		return SignOutput{}, err
	}
	defer releaseData()

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
	tsaURL := in.TSAURL
	if tsaURL == "" {
		tsaURL = s.defaultTSAURL
	}

	// The library anchors the signer's chain only when the time check is on, so
	// the CA(s) are loaded just for that path — a permissive sign needs no store.
	var trusted []provider.TrustedCert
	if !in.NoCheckCertTime {
		trusted = toProviderCerts(s.mergedTrusted(in.TrustedCerts))
	}

	var res provider.SignResult
	switch in.Format {
	case FormatCMS:
		res, err = s.prov.SignCMS(ctx, provider.SignRequest{
			Key:               handle.Ref,
			Data:              in.Data,
			Path:              dataPath,
			Detached:          in.Detached,
			InputPEM:          in.InputPEM,
			OutPEM:            in.OutputPEM,
			CheckCertTime:     !in.NoCheckCertTime,
			WithTimestamp:     withTS,
			TSAURL:            tsaURL,
			ExistingSignature: in.ExistingSignature,
			TrustedCerts:      trusted,
		})
	case FormatXML:
		res, err = s.prov.SignXML(ctx, provider.SignXMLRequest{
			Key:           handle.Ref,
			XML:           in.Data,
			CheckCertTime: !in.NoCheckCertTime,
			WithTimestamp: withTS,
			TSAURL:        tsaURL,
			NodeID:        in.NodeID,
			ParentNode:    in.ParentNode,
			ParentNS:      in.ParentNS,
			TrustedCerts:  trusted,
		})
	case FormatWSSE:
		res, err = s.prov.SignWSSE(ctx, provider.SignWSSERequest{
			Key:           handle.Ref,
			XML:           in.Data,
			NodeID:        in.NodeID,
			CheckCertTime: !in.NoCheckCertTime,
			WithTimestamp: withTS,
			TSAURL:        tsaURL,
			TrustedCerts:  trusted,
		})
	}
	if err != nil {
		s.recordAudit(ctx, AuditEvent{Op: "sign", Subject: digestOf(in.Data), Outcome: "error"})
		return SignOutput{Format: in.Format, LibError: libErrorFrom(ctx, err)}, domainErr(op, err)
	}
	// The digest of the produced signature identifies the artifact without copying
	// it (or the content) into the journal.
	s.recordAudit(ctx, AuditEvent{Op: "sign", Subject: digestOf(res.Signature), Outcome: "ok"})

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
	if in.DataRef.IsRef() && in.Format != FormatCMS {
		return VerifyOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("by-reference data supported for CMS only")}
	}
	dataPath, releaseData, err := s.resolveData(ctx, op, in.DataRef)
	if err != nil {
		return VerifyOutput{}, err
	}
	defer releaseData()

	var w warnings
	trusted := s.mergedTrusted(in.TrustedCerts)
	req := provider.VerifyRequest{
		Signature:     in.Signature,
		Data:          in.Data,
		Path:          dataPath,
		Detached:      in.Detached,
		InputPEM:      in.InputPEM,
		OutPEM:        true,
		CheckCertTime: in.CheckCertTime,
		TrustedCerts:  toProviderCerts(trusted),
	}

	res, err := s.verifyContainer(ctx, in.Format, req)
	// When verification fails only because the signer's issuing CA is not a loaded
	// anchor (the library reports this as a cert-time/chain error), discover the
	// missing intermediates via AIA from the returned signer certs and retry once
	// with them added — so a real leaf whose issuing CA is reachable but not
	// preconfigured still anchors. Only on the failure path, so the common case
	// pays nothing.
	if s.fetcher != nil && in.CheckCertTime && isAnchorFailure(err) && len(res.Signers) > 0 {
		if extra := s.discoverAnchors(ctx, signerDERs(res.Signers), trusted); len(extra) > 0 {
			trusted = append(trusted, extra...)
			req.TrustedCerts = toProviderCerts(trusted)
			res, err = s.verifyContainer(ctx, in.Format, req)
		}
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

	// Cert-time-anchor override. Some GOST-2015 chains make Kalkan's time-checked
	// VerifyData reject with 0x08F00042 even though the chain is loaded and valid —
	// its monolithic verdict is unreliable here (its own X509ValidateCertificate
	// anchors the same chain fine, i.e. chainSignaturesVerified). When that happens
	// and our independent verification confirms the signature — the signature math
	// alone (VerifyData without the cert-time gate), the cryptographic chain to a
	// trusted anchor, and every signer within its validity window — we trust that
	// composite verdict. It is strictly stronger than the library's, never weaker:
	// all four facts must hold. Gated on chain verification (the GOST-capable check).
	if !out.Valid && s.verifyChain && in.CheckCertTime && isAnchorFailure(err) &&
		s.compositeConfirms(ctx, req, in.Format, out.Signers) {
		out.Valid = true
		err = nil
		for i := range out.Signers {
			out.Signers[i].Valid = true
		}
		w.add("verify", "cert-time-anchor-override: library rejected the time-checked verify (GOST-2015 VerifyData quirk); signature math, cryptographic chain to a trusted anchor and validity window independently confirm the signature")
	}

	// Revocation is checked only once the signature itself holds up: contacting a
	// responder about a container that did not verify buys nothing, and the
	// verdict is already invalid either way.
	if out.Valid && in.RevocationRequested() {
		ocsp := s.checkRevocation(ctx, &out, in, trusted, &w)
		if in.Archive {
			s.attachArchive(&out, in, ocsp, &w)
		}
	}

	// A verdict with no signer names nobody. The library can return "the maths
	// held" while the signer walk yields nothing (a container encoding it verifies
	// but cannot enumerate), and "valid" without a single signer is worse than a
	// refusal for a caller that reads only that field.
	if out.Valid && len(out.Signers) == 0 {
		out.Valid = false
		w.add("verify", "the signature verified but no signer could be identified; a verdict that names nobody is not a verdict")
	}

	out.Warnings = w.list()

	if err != nil {
		if isSoftVerifyFailure(err) {
			out.LibError = libErrorFrom(ctx, err)
			s.attachSynthesis(ctx, &out, in)
			return out, nil
		}
		return out, domainErr(op, err)
	}
	s.attachSynthesis(ctx, &out, in)
	return out, nil
}

// checkRevocation fills in each signer's revocation status and returns the raw
// OCSP responses, which archiving reuses as its evidence. A revoked signer makes
// the whole verification invalid: the signature math still holds, but the key it
// was made with has been repudiated, and a caller reading `valid` must not have
// to also remember to read a separate field to learn that.
//
// A check that could not be completed leaves the status indeterminate rather
// than "not revoked" — the library reports an unreachable responder as a soft
// failure with Revoked false, which is the same shape as a clean answer.
func (s *Service) checkRevocation(ctx context.Context, out *VerifyOutput, in VerifyInput, trusted []TrustedCert, w *warnings) [][]byte {
	method := in.RevocationMethod
	if method == "" {
		method = MethodOCSP
	}
	var responses [][]byte
	for i := range out.Signers {
		field := fmt.Sprintf("signers[%d].revocation", i)
		cert := out.Signers[i].Certificate
		if len(cert.PEM) == 0 {
			w.add(field, "no certificate to check revocation for")
			continue
		}
		res, err := s.Validate(ctx, ValidateInput{
			Cert:         cert.PEM,
			Format:       EncodingPEM,
			Method:       method,
			ResponderURL: in.ResponderURL,
			WantOCSP:     in.Archive,
			TrustedCerts: trusted,
		})
		if err != nil {
			w.addErr(field, err)
			out.Signers[i].Revocation = &RevocationStatus{Method: method}
			continue
		}
		status := res.Status
		out.Signers[i].Revocation = &status
		switch {
		case !status.Determinate:
			w.add(field, "revocation status could not be established")
		case status.Revoked:
			out.Valid = false
			out.Signers[i].Valid = false
		}
		switch {
		case len(res.OCSPResponse) > 0:
			responses = append(responses, res.OCSPResponse)
		case in.Archive:
			// The chain is still worth embedding, but an archive without the
			// revocation proof loses exactly the part that expires with the
			// responder — so say so rather than quietly shipping a thinner archive.
			w.add(field, "responder returned no reusable response to embed")
		}
	}
	return responses
}

// attachArchive embeds this verification's evidence into the container. The
// responses are the ones the revocation check just obtained, so the archive and
// the verdict rest on the same evidence — the reason archiving is worth doing
// here rather than in a second pass that re-asks the responder.
func (s *Service) attachArchive(out *VerifyOutput, in VerifyInput, ocsp [][]byte, w *warnings) {
	if in.Format != FormatCMS {
		w.add("archive", "long-term validation evidence can only be embedded into CMS")
		return
	}
	evidence := cms.Evidence{OCSPResponses: ocsp}
	for _, signer := range out.Signers {
		// The chain travels with the signature: an issuer certificate that is easy
		// to fetch today may not be fetchable at all when the archive is opened.
		for _, c := range signer.Chain {
			if der := toDER(c.PEM, EncodingPEM); len(der) > 0 {
				evidence.Certificates = append(evidence.Certificates, der)
			}
		}
	}
	// The archived container comes back in the encoding the caller sent.
	archived, err := embedEvidence(in.Signature, in.InputPEM, in.InputPEM, evidence)
	if err != nil {
		w.addErr("archive", err)
		return
	}
	out.Archive = &archived
}

// attachSynthesis adds the requested plain-language views of a completed
// verification. Both are pure synthesis over the result — no extra crypto, no
// network — so they are equally available on every transport and inside batches.
func (s *Service) attachSynthesis(ctx context.Context, out *VerifyOutput, in VerifyInput) {
	now := s.now()
	if in.Explain {
		out.Explanation = buildDiagnosis(*out, in.CheckCertTime, s.verifyChain, now)
	}
	if in.Report || in.Receipt {
		out.Report = buildReport(*out, in.CheckCertTime, s.verifyChain, in.Signature, out.Content, now)
	}
	if in.Receipt {
		token, err := s.issueReceipt(out.Report, now)
		if err != nil {
			out.Warnings = append(out.Warnings, Warning{Field: "receipt", Reason: err.Error()})
		}
		out.Receipt = token
	}
	// The journal records the digest of what was checked, never the content: an
	// audit trail must not become a copy of every document that passed through.
	if s.audit != nil {
		ev := AuditEvent{Op: "verify", Subject: digestOf(in.Signature), Outcome: "invalid"}
		if out.Valid {
			ev.Outcome = "valid"
		}
		if len(out.Signers) > 0 {
			subj := out.Signers[0].Certificate.Subject
			ev.Signer = firstNonEmptyString(subj.IIN, subj.BIN, subj.CommonName)
		}
		if out.LibError != nil {
			ev.Detail = out.LibError.Key
		}
		s.audit.Record(ctx, ev)
	}
	// The report was only built to sign; drop it unless the caller asked for it.
	if !in.Report {
		out.Report = nil
	}
}

// recordAudit reports an operation to the journal when one is configured.
func (s *Service) recordAudit(ctx context.Context, ev AuditEvent) {
	if s.audit != nil {
		s.audit.Record(ctx, ev)
	}
}

// firstNonEmptyString returns the first non-empty value.
func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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
		out.LibError = libErrorFrom(ctx, err)
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

	out := CertInfoOutput{Certificate: cert, Algorithm: algorithmInfo(cert), Warnings: w.list()}
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

	var w warnings
	certDER := toDER(in.Cert, in.Format)

	// Anchor the certificate: discover its issuing CAs via AIA (when enabled) and
	// add them to the trusted set, so a real leaf whose intermediate is reachable
	// but not preconfigured can be validated rather than failing to anchor.
	trusted := s.mergedTrusted(in.TrustedCerts)
	if s.fetcher != nil {
		trusted = append(trusted, s.discoverAnchors(ctx, [][]byte{certDER}, trusted)...)
	}

	// Resolve the effective method and any CRL material, applying the CRL fail
	// policy. effMethod may switch CRL→OCSP on a soft failure.
	effMethod := method
	// Path: OCSP responder URL, or a temp file for a CRL (Kalkan reads a path).
	path := in.ResponderURL
	wantOCSP := in.WantOCSP || method == MethodOCSP
	var crlBytes, deltaBytes []byte

	if method == MethodCRL {
		switch {
		case len(in.CRL) > 0:
			crlBytes = in.CRL // caller-supplied CRL: trusted to the caller, used as-is
		case s.crl != nil:
			res, ok := s.crl.CRLFor(ctx, certDER)
			switch {
			case ok && res.Reliable:
				crlBytes, deltaBytes = res.Base, res.Delta
			case s.crlFailPolicy == CRLFailHard:
				reason := crlReason(res, ok)
				return ValidateOutput{}, &Error{Kind: KindInvalid, Op: op,
					err: fmt.Errorf("CRL revocation status could not be established (%s); fail policy is hard", reason)}
			default:
				// Soft fail: OCSP is authoritative for real-time status — fall back.
				effMethod = MethodOCSP
				wantOCSP = true
				w.add("crl", "fallback-to-ocsp:"+crlReason(res, ok))
			}
		}
		// s.crl == nil and no inline CRL: leave crlBytes empty, as before (the
		// library path handles the absent CRL).
	}

	// An OCSP check with no responder named falls through to the library's
	// built-in default, which is the production responder: it knows nothing about
	// a certificate from a test CA, and the caller gets a failure that reads as
	// "not revoked" unless they look at determinate. The responder the issuer
	// published in the certificate's AIA is the one that can answer for it.
	if effMethod == MethodOCSP && path == "" {
		path = ocspURLFromCert(certDER)
		if path == "" {
			// Guessing the responder is what made this silent in the first place, so
			// a certificate that names none leaves the status undetermined.
			w.add("revocation", "the certificate publishes no OCSP responder (AIA); pass responderUrl to name one")
			checked := checkTime
			return ValidateOutput{
				Status:   RevocationStatus{Method: effMethod, CheckedAt: &checked},
				Warnings: w.list(),
			}, nil
		}
	}

	// A cached OCSP answer skips the native call entirely — that is what spares the
	// responder. Only the OCSP path is cacheable: a CRL check is answered from
	// material the caller or the CRL layer already holds.
	if effMethod == MethodOCSP && s.ocspCache != nil {
		if answer, ok := s.ocspCache.Lookup(certDER, path); ok {
			return s.cachedValidateOutput(in, effMethod, checkTime, answer, w), nil
		}
	}

	if effMethod == MethodCRL && len(crlBytes) > 0 {
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
		Method:       validationMethod(effMethod),
		Path:         path,
		CheckTime:    checkTime,
		WantOCSP:     wantOCSP,
		TrustedCerts: toProviderCerts(trusted),
	})

	checked := checkTime
	status := RevocationStatus{
		Method:  effMethod,
		Revoked: res.Status == provider.StatusRevoked,
		// An unknown status is not "not revoked": the responder did not say.
		Determinate: res.Status != provider.StatusUnknown,
		CheckedAt:   &checked,
	}
	// Enrich with structured fields parsed from the response/CRL (best-effort).
	if effMethod == MethodOCSP {
		enrichFromOCSP(&status, res.OCSPResponse, res.Info)
	} else if len(crlBytes) > 0 {
		enrichFromCRL(&status, crlBytes, certDER)
		// A consistent delta may carry a revocation not yet in the base CRL. The
		// library verified the base; overlay the delta structurally (safe
		// direction: it can only add a revocation, never clear one).
		if !status.Revoked && len(deltaBytes) > 0 {
			enrichFromCRL(&status, deltaBytes, certDER)
		}
	}

	out := ValidateOutput{Status: status, Info: res.Info}
	if in.WantOCSP {
		out.OCSPResponse = res.OCSPResponse
	}
	if err != nil {
		if isSoftVerifyFailure(err) {
			// The library reports an unreachable responder as a soft failure with
			// Revoked false — the same shape as a clean answer, so the status has to
			// be marked undetermined explicitly.
			out.Status.LibError = libErrorFrom(ctx, err)
			out.Status.Determinate = false
			out.Warnings = w.list()
			return out, nil
		}
		return out, domainErr(op, err)
	}
	// Only a clean answer is worth caching: a failed check would otherwise pin its
	// own failure for the whole TTL.
	if effMethod == MethodOCSP && s.ocspCache != nil {
		s.ocspCache.Store(certDER, path, OCSPAnswer{
			Revoked:        status.Revoked,
			Reason:         status.Reason,
			RevocationTime: status.RevocationTime,
			ThisUpdate:     status.ThisUpdate,
			NextUpdate:     status.NextUpdate,
			ProducedAt:     status.ProducedAt,
			Response:       res.OCSPResponse,
		})
	}
	out.Warnings = w.list()
	return out, nil
}

// cachedValidateOutput renders a cache hit as a normal validation result. The
// verdict and its freshness fields come from the responder's own answer; only
// CheckedAt is now, because that is when this caller was told.
func (s *Service) cachedValidateOutput(in ValidateInput, method ValidationMethod, checkTime time.Time, a OCSPAnswer, w warnings) ValidateOutput {
	checked := checkTime
	out := ValidateOutput{Status: RevocationStatus{
		Method: method,
		// Only clean answers are cached, so a hit is always a determined one.
		Determinate:    true,
		Revoked:        a.Revoked,
		Reason:         a.Reason,
		RevocationTime: a.RevocationTime,
		CheckedAt:      &checked,
		ThisUpdate:     a.ThisUpdate,
		NextUpdate:     a.NextUpdate,
		ProducedAt:     a.ProducedAt,
	}}
	if in.WantOCSP {
		out.OCSPResponse = a.Response
	}
	out.Warnings = w.list()
	return out
}

// crlReason names why a managed CRL is unusable, for warnings and hard-fail
// messages. ok is the CRLFor availability flag.
func crlReason(res CRLResult, ok bool) string {
	if !ok {
		return "unavailable"
	}
	if res.Reason != "" {
		return res.Reason
	}
	return "unreliable"
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
				// CAdES-T claims a genuine timestamp *over this signature*, so both
				// halves have to hold: the imprint binds the token to this signature
				// (a token can otherwise be lifted from another container unchanged),
				// and the TSA actually signed the token (an imprint alone proves only
				// that someone built a structure naming this signature).
				imprint, inote := s.verifyTimestampImprint(ctx, si)
				sig.Timestamp.ImprintVerified, sig.Timestamp.ImprintNote = imprint, inote
				signed, snote := s.verifyTimestampSignature(ctx, si.Timestamp, trusted)
				sig.Timestamp.SignatureVerified, sig.Timestamp.SignatureNote = signed, snote
				pname, paccepted, pnote := s.checkTimestampPolicy(sig.Timestamp.Policy)
				sig.Timestamp.PolicyName = pname
				sig.Timestamp.PolicyAccepted, sig.Timestamp.PolicyNote = paccepted, pnote
				// A policy verdict only blocks when the operator asked for one; an
				// absent allow-list leaves paccepted nil and changes nothing.
				policyRefused := paccepted != nil && !*paccepted
				switch {
				case imprint != nil && *imprint && signed != nil && *signed && !policyRefused:
					sig.CAdESLevel = "T"
				default:
					note := firstNonEmptyString(inote, snote)
					if policyRefused {
						note = pnote
					}
					w.add(fmt.Sprintf("signers[%d].timestamp", i), timestampWarning(note))
				}
			}
		}
		if sig.SignatureAlgorithm == "" {
			sig.SignatureAlgorithm = cert.SignatureAlgorithm
		}
		// Fallback: Kalkan's genTime for the first signer when no CMS token parsed.
		// It is a time, not a token — there is nothing to check the imprint against,
		// so the timestamp is reported without claiming CAdES-T for it.
		if sig.Timestamp == nil && i == 0 && !res.Timestamp.IsZero() {
			t := res.Timestamp.UTC()
			sig.Timestamp = &Timestamp{GenTime: &t,
				ImprintNote: "only the library's genTime was available; the token itself could not be read or checked"}
		}
		signers = append(signers, sig)
	}
	return signers
}

// timestampWarning renders why a timestamp was not accepted as CAdES-T.
func timestampWarning(note string) string {
	if note == "" {
		note = "the token's message imprint could not be checked"
	}
	return "timestamp present but not accepted as CAdES-T: " + note
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

// verifyContainer dispatches to the CMS or XML verify per format.
func (s *Service) verifyContainer(ctx context.Context, format SignatureFormat, req provider.VerifyRequest) (provider.VerifyResult, error) {
	if format == FormatCMS {
		return s.prov.VerifyCMS(ctx, req)
	}
	return s.prov.VerifyXML(ctx, req)
}

// isAnchorFailure reports whether a verify error is the kind a missing issuing-CA
// anchor produces: the library surfaces an absent trusted CA as a cert-time or
// chain error (0x08F00042 and kin), not a distinct code, so a retry with the
// discovered intermediate can turn it into success.
func isAnchorFailure(err error) bool {
	return errors.Is(err, provider.ErrCertTimeInvalid) ||
		errors.Is(err, provider.ErrChainInvalid) ||
		errors.Is(err, provider.ErrCARequired)
}

// signerDERs converts PEM signer certificates to DER for chain building.
func signerDERs(pemCerts [][]byte) [][]byte {
	out := make([][]byte, 0, len(pemCerts))
	for _, p := range pemCerts {
		if der := toDER(p, EncodingPEM); len(der) > 0 {
			out = append(out, der)
		}
	}
	return out
}

// discoverAnchors builds each leaf's chain via AIA issuer fetch and returns the CA
// nodes not already in trusted, as trusted certs (a self-issued node is a root,
// otherwise an intermediate). These are the issuing CAs the library must load to
// anchor a chain whose intermediate is reachable but not preconfigured. Requires a
// fetcher; returns nil otherwise.
func (s *Service) discoverAnchors(ctx context.Context, leavesDER [][]byte, trusted []TrustedCert) []TrustedCert {
	if s.fetcher == nil {
		return nil
	}
	have := make(map[string]bool, len(trusted))
	for _, tc := range trusted {
		have[string(toDER(tc.Cert, EncodingPEM))] = true
	}
	var extra []TrustedCert
	for _, der := range leavesDER {
		chain, _, _ := buildChain(ctx, Certificate{}, der, trusted, s.fetcher)
		for _, node := range chain[1:] { // CA nodes above the leaf
			key := string(toDER(node.PEM, EncodingPEM))
			if have[key] {
				continue
			}
			have[key] = true
			extra = append(extra, TrustedCert{Cert: node.PEM, Intermediate: !nodeIsRoot(node.PEM)})
		}
	}
	return extra
}

// compositeConfirms independently confirms a signature the library rejected only
// on the cert-time/anchor gate: every signer must be cryptographically chained to a
// trusted anchor (chainSignaturesVerified + trustAnchorFound) and within its
// validity window at now, and the signature math must verify on its own — a repeat
// verify with the cert-time gate off. All must hold; any miss returns false.
func (s *Service) compositeConfirms(ctx context.Context, req provider.VerifyRequest, format SignatureFormat, signers []Signer) bool {
	if len(signers) == 0 {
		return false
	}
	now := s.now()
	for i := range signers {
		if !signers[i].ChainSignaturesVerified || !signers[i].TrustAnchorFound {
			return false
		}
		c := signers[i].Certificate
		if c.NotBefore == nil || c.NotAfter == nil || now.Before(*c.NotBefore) || now.After(*c.NotAfter) {
			return false
		}
	}
	// Confirm the signature math with the cert-time gate off (the gate is exactly
	// what misfired; the rest of the verify is unchanged).
	sigReq := req
	sigReq.CheckCertTime = false
	res, err := s.verifyContainer(ctx, format, sigReq)
	return err == nil && res.Valid
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

// resolveData turns an optional by-reference payload into a driver-readable path.
// It returns the path (empty when the payload is inline) and a release func that
// is always safe to call. A reference with no configured resolver is a clear
// KindUnavailable error rather than a silent fallback to inline.
func (s *Service) resolveData(ctx context.Context, op string, ref DataRef) (path string, release func(), err error) {
	if !ref.IsRef() {
		return "", func() {}, nil
	}
	if s.dataResolver == nil {
		return "", func() {}, &Error{Kind: KindUnavailable, Op: op, err: errors.New("by-reference data requires a configured data resolver")}
	}
	rd, rerr := s.dataResolver.Resolve(ctx, ref)
	if rerr != nil {
		var de *Error
		if errors.As(rerr, &de) {
			return "", func() {}, rerr // already a classified domain error
		}
		return "", func() {}, domainErr(op, rerr)
	}
	return rd.Path, rd.Release, nil
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
