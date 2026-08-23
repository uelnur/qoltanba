package core

import (
	"context"
	"errors"
	"time"
)

// Point-in-time (historical) verification: "was this signature valid at instant
// X", not "is it valid now". The temporal question decomposes into three facts
// evaluated at X, layered on top of the ordinary Verify (which supplies the
// signature math, the signer certificates and the chain):
//
//  1. the signature verifies cryptographically (time-independent);
//  2. the signer certificate was inside its validity window at X
//     (notBefore ≤ X ≤ notAfter);
//  3. the certificate was not revoked as of X.
//
// The third fact is the subtle one. OCSP and CRL report the *current* status,
// but revocation is monotonic (a certificate, once revoked, stays revoked — the
// one reversible reason, certificateHold, is flagged as a caveat). So a current
// status plus its revocationTime answers the past: revoked-as-of-X ⟺
// X ≥ revocationTime. A certificate good today was therefore good at any earlier
// instant; a certificate revoked today was good at X iff X predates the
// revocation. An archived CRL closest to X (supplied inline) is more precise and
// authoritative for a disputed instant, but the current OCSP path already yields
// a sound verdict for the common case.
//
// This differs from LTV, which *preserves* validation evidence at signing time;
// here we *reconstruct* the verdict for a past instant from present-day sources.

// VerifyAtInput asks whether a signature was valid at the instant At, rather than
// now. It embeds a standard VerifyInput (same signature/format/trust inputs) and
// adds the instant plus the revocation source used to reconstruct past status.
type VerifyAtInput struct {
	VerifyInput

	// At is the past instant to evaluate validity at. Required; a zero or future
	// value is rejected.
	At time.Time

	// Method selects how the signer's revocation status is obtained (default
	// OCSP). OCSP is authoritative and, being monotonic, places past status via
	// revocationTime. CRL with an archived list (CRL below) is more precise for a
	// disputed instant.
	Method ValidationMethod
	// CRL is an inline (ideally archived-at-At) CRL for Method=CRL.
	CRL []byte
	// ResponderURL overrides the OCSP responder (empty uses the NUC default).
	ResponderURL string
}

// PointInTimeVerdict is one signer's historical validity assessment at At.
type PointInTimeVerdict struct {
	At          time.Time `json:"at"`
	ValidAt     bool      `json:"validAt"`
	Determinate bool      `json:"determinate"` // false when data was insufficient to be sure

	SignatureValid bool `json:"signatureValid"`

	// Certificate time-validity at At.
	WithinValidity bool       `json:"withinValidity"`
	NotBefore      *time.Time `json:"notBefore,omitempty"`
	NotAfter       *time.Time `json:"notAfter,omitempty"`

	// Revocation as of At.
	NotRevokedAt     bool             `json:"notRevokedAt"`
	RevokedAsOfAt    bool             `json:"revokedAsOfAt,omitempty"`
	RevocationTime   *time.Time       `json:"revocationTime,omitempty"`
	RevocationReason string           `json:"revocationReason,omitempty"`
	Method           ValidationMethod `json:"method,omitempty"`

	// Reasons explain the verdict and record caveats (reversible hold,
	// inconclusive revocation data, missing validity window). Human-readable.
	Reasons []string `json:"reasons,omitempty"`
}

// SignerAt pairs a signer (the full standard view) with its point-in-time verdict.
type SignerAt struct {
	Signer  Signer             `json:"signer"`
	Verdict PointInTimeVerdict `json:"verdict"`
}

// VerifyAtOutput is the historical verification outcome. ValidAt/Determinate are
// the conjunction over every signer (a signature is valid at At only if all its
// signers were).
type VerifyAtOutput struct {
	At          time.Time       `json:"at"`
	ValidAt     bool            `json:"validAt"`
	Determinate bool            `json:"determinate"`
	Format      SignatureFormat `json:"format,omitempty"`
	Detached    bool            `json:"detached"`
	Signers     []SignerAt      `json:"signers,omitempty"`
	Warnings    []Warning       `json:"warnings,omitempty"`
	LibError    *LibError       `json:"libError,omitempty"`
}

// VerifyAt reconstructs whether a signature was valid at a past instant. It runs
// the ordinary verification (signature math + signer extraction) and then, per
// signer, evaluates the certificate's validity window and revocation status as of
// At. Like Verify, a signature that simply is not valid-at-At is a business result
// (ValidAt=false), not a transport error; only infrastructure faults return err.
func (s *Service) VerifyAt(ctx context.Context, in VerifyAtInput) (VerifyAtOutput, error) {
	const op = "VerifyAt"
	if in.At.IsZero() {
		return VerifyAtOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("point-in-time instant (at) is required")}
	}
	if in.At.After(s.now()) {
		return VerifyAtOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("point-in-time instant is in the future")}
	}
	at := in.At.UTC()

	// Verify the signature math and extract signers. Force the library cert-time
	// check off: it checks against the system clock and would reject a
	// today-expired-but-then-valid certificate — the exact case this feature
	// exists for. Time-validity is evaluated against At below instead.
	vin := in.VerifyInput
	vin.CheckCertTime = false
	// The inline revocation check answers "is it revoked now", which would sink a
	// signature that was perfectly good at At and revoked afterwards — the other
	// case this feature exists for. Revocation as of At is reconstructed below,
	// from the current status plus the monotonicity of revocation.
	off := false
	vin.RevocationCheck = &off
	vout, err := s.Verify(ctx, vin)
	if err != nil {
		return VerifyAtOutput{}, err
	}

	out := VerifyAtOutput{
		At:       at,
		Format:   vout.Format,
		Detached: vout.Detached,
		Warnings: vout.Warnings,
		LibError: vout.LibError,
	}
	if len(vout.Signers) == 0 {
		// No verifiable signer: definitively not valid, and we are sure of it.
		out.Determinate = true
		return out, nil
	}

	allValid, allDeterminate := true, true
	for i := range vout.Signers {
		verdict := s.assessSignerAt(ctx, vout.Signers[i], at, in)
		out.Signers = append(out.Signers, SignerAt{Signer: vout.Signers[i], Verdict: verdict})
		allValid = allValid && verdict.ValidAt
		allDeterminate = allDeterminate && verdict.Determinate
	}
	out.ValidAt = allValid
	out.Determinate = allDeterminate
	return out, nil
}

// assessSignerAt builds one signer's point-in-time verdict: signature math from
// the verify result, the certificate's validity window against At, and revocation
// status as of At (reconstructed from the current status via revocationTime).
func (s *Service) assessSignerAt(ctx context.Context, signer Signer, at time.Time, in VerifyAtInput) PointInTimeVerdict {
	v := PointInTimeVerdict{
		At:             at,
		SignatureValid: signer.Valid,
		NotBefore:      signer.Certificate.NotBefore,
		NotAfter:       signer.Certificate.NotAfter,
	}
	if !signer.Valid {
		v.Reasons = append(v.Reasons, "signature did not verify")
	}

	within, timeDeterminate := withinValidityAt(signer.Certificate, at)
	v.WithinValidity = within
	switch {
	case !timeDeterminate:
		v.Reasons = append(v.Reasons, "certificate validity window unknown (notBefore/notAfter absent)")
	case !within:
		v.Reasons = append(v.Reasons, "certificate was outside its validity window at the requested instant")
	}

	notRevoked, revDeterminate := s.revocationAt(ctx, signer.Certificate, at, in, &v)
	v.NotRevokedAt = notRevoked

	v.Determinate = timeDeterminate && revDeterminate
	v.ValidAt = signer.Valid && within && notRevoked
	return v
}

// withinValidityAt reports whether at falls in [notBefore, notAfter]. determinate
// is false when either bound is missing (the window cannot be judged).
func withinValidityAt(c Certificate, at time.Time) (within, determinate bool) {
	if c.NotBefore == nil || c.NotAfter == nil {
		return false, false
	}
	return !at.Before(*c.NotBefore) && !at.After(*c.NotAfter), true
}

// revocationAt reconstructs the certificate's revocation status as of at from the
// current status. It fills the revocation fields/caveats on v and returns whether
// the certificate was not revoked at at, and whether that answer is determinate.
//
// Monotonicity: a certificate not revoked now was not revoked earlier; a
// certificate revoked now was revoked at at iff at ≥ revocationTime. When the
// current status is revoked but carries no revocationTime, or the check is
// inconclusive (e.g. an OCSP responder that no longer answers for an expired
// certificate), the answer is left indeterminate rather than guessed.
func (s *Service) revocationAt(ctx context.Context, cert Certificate, at time.Time, in VerifyAtInput, v *PointInTimeVerdict) (notRevoked, determinate bool) {
	if len(cert.PEM) == 0 {
		v.Reasons = append(v.Reasons, "revocation status not checked (signer certificate unavailable)")
		return true, false
	}
	res, err := s.Validate(ctx, ValidateInput{
		Cert:         cert.PEM,
		Format:       EncodingPEM,
		Method:       in.Method,
		CheckTime:    at,
		ResponderURL: in.ResponderURL,
		CRL:          in.CRL,
	})
	if err != nil {
		v.Reasons = append(v.Reasons, "revocation status could not be determined: "+err.Error())
		return true, false
	}
	st := res.Status
	v.Method = st.Method

	// The library could not produce a status (e.g. responder refused an expired
	// cert). Not proven revoked, but we cannot be sure — indeterminate.
	if st.LibError != nil && !st.Revoked {
		v.Reasons = append(v.Reasons, "revocation check inconclusive ("+st.LibError.Code+"); an archived CRL at the instant would be authoritative")
		return true, false
	}
	if !st.Revoked {
		return true, true // monotonic: good now ⇒ good at any earlier instant
	}

	// Revoked now — place the revocation relative to at.
	if st.Reason != "" {
		v.RevocationReason = st.Reason
	}
	if st.RevocationTime == nil {
		v.Reasons = append(v.Reasons, "certificate is revoked but the revocation time is unknown; it cannot be placed relative to the requested instant")
		return false, false
	}
	rt := st.RevocationTime.UTC()
	v.RevocationTime = &rt
	if st.Reason == "certificateHold" {
		v.Reasons = append(v.Reasons, "revocation reason is certificateHold, which is reversible; a hold may have been lifted later — an archived CRL at the instant is authoritative")
	}

	revokedAsOfAt := !at.Before(rt) // at ≥ revocationTime
	v.RevokedAsOfAt = revokedAsOfAt
	if revokedAsOfAt {
		v.Reasons = append(v.Reasons, "certificate was already revoked at the requested instant")
		return false, true
	}
	v.Reasons = append(v.Reasons, "certificate was revoked after the requested instant, so it was still valid then")
	return true, true
}
