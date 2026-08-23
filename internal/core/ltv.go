package core

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/uelnur/qoltanba/internal/cms"
)

// Long-term validation: turning a signature that verifies *today* into one that
// still verifies years from now.
//
// Verification depends on things that do not last: an OCSP responder that answers,
// a CA that is still online, a certificate inside its validity window. The
// signature itself stays mathematically sound far longer than that infrastructure.
// Archiving collects the evidence while it is still obtainable and embeds it in
// the container, so a future verifier can reach the same verdict offline.
//
// This produces CAdES-LT. LTA — an archive timestamp over the completed structure
// — is not produced: it needs a fresh TSA round trip over the finished container,
// which is a separate operation on a different schedule (re-stamping before the
// stamp's own algorithms age), not part of packaging evidence.

// ArchiveInput asks for the evidence to be collected and embedded.
type ArchiveInput struct {
	// Signature is the CMS container (PEM or DER).
	Signature []byte
	InputPEM  bool
	// Data is the signed content for a detached signature, needed to identify the
	// signers whose evidence is collected.
	Data     []byte
	Detached bool
	// ResponderURL overrides the OCSP responder.
	ResponderURL string
	// TrustedCerts are extra anchors for building the signer's chain.
	TrustedCerts []TrustedCert
	// OutputPEM returns the archived container PEM-wrapped.
	OutputPEM bool
	// AllowRevoked archives a signature whose signer has been revoked. Off by
	// default: reporting "archived" for a repudiated signature is how a caller
	// ends up filing evidence of the wrong thing. Preserving proof about a
	// revoked signature is a real need (a dispute over what was signed before the
	// revocation), so it stays possible — but only on request.
	AllowRevoked bool
}

// ArchiveOutput is the container with evidence embedded.
type ArchiveOutput struct {
	Signature []byte `json:"signature"`
	// Embedded counts what was put in, so a caller can see the archive actually
	// gained something.
	Embedded ArchiveEvidence `json:"embedded"`
	// Level is the level reached: "LT" once evidence is embedded.
	Level    string    `json:"level"`
	Warnings []Warning `json:"warnings,omitempty"`
}

// ArchiveEvidence counts the embedded material.
type ArchiveEvidence struct {
	OCSPResponses int `json:"ocspResponses"`
	CRLs          int `json:"crls"`
	Certificates  int `json:"certificates"`
}

// Archive embeds long-term validation evidence into a signature: the OCSP
// responses proving its signers were not revoked, and the chain certificates a
// future verifier will not be able to fetch.
//
// It is a verification that also keeps its evidence, not a separate collection
// pass — so the material embedded is exactly the material the verdict rests on,
// and the checks a verdict implies (the signature holds, the signer is not
// revoked) are the checks archiving enforces.
//
// It refuses to produce an "archived" container with nothing in it: a caller who
// thinks a document is preserved when it is not is worse off than one who gets an
// error today, while the evidence is still obtainable.
func (s *Service) Archive(ctx context.Context, in ArchiveInput) (ArchiveOutput, error) {
	const op = "Archive"
	if len(in.Signature) == 0 {
		return ArchiveOutput{}, &Error{Kind: KindInvalid, Op: op, err: errors.New("signature is required")}
	}

	verified, err := s.Verify(ctx, VerifyInput{
		Format:        FormatCMS,
		Signature:     in.Signature,
		Data:          in.Data,
		Detached:      in.Detached,
		InputPEM:      in.InputPEM,
		CheckCertTime: false, // an expired signer is exactly what archiving is for
		TrustedCerts:  in.TrustedCerts,
		ResponderURL:  in.ResponderURL,
		Archive:       true,
	})
	if err != nil {
		return ArchiveOutput{}, domainErr(op, err)
	}
	if len(verified.Signers) == 0 {
		return ArchiveOutput{}, &Error{Kind: KindInvalid, Op: op,
			err: errors.New("container carries no signers to collect evidence for")}
	}
	if revoked := revokedSigners(verified.Signers); len(revoked) > 0 {
		if !in.AllowRevoked {
			return ArchiveOutput{}, &Error{Kind: KindInvalid, Op: op, err: fmt.Errorf(
				"signer certificate is revoked (%s); archiving it would file evidence of a repudiated signature — set allowRevoked to do it deliberately",
				strings.Join(revoked, ", "))}
		}
	} else if !verified.Valid {
		// Checked after revocation so the revoked case gets its own message: a
		// revoked signer also lands here, and "does not verify" would hide why.
		return ArchiveOutput{}, &Error{Kind: KindInvalid, Op: op,
			err: errors.New("the container does not verify; archiving it would preserve a signature that is already broken")}
	}
	if verified.Archive == nil {
		return ArchiveOutput{Warnings: verified.Warnings}, &Error{Kind: KindUnavailable, Op: op,
			err: errors.New("no long-term validation evidence could be collected (responder unreachable, or nothing to embed)")}
	}

	out := *verified.Archive
	out.Warnings = append(out.Warnings, verified.Warnings...)
	if in.OutputPEM != in.InputPEM {
		// Verify returns the container in the encoding it was given; re-encode only
		// when the caller asked for the other one.
		reencoded, rerr := reencodeCMS(out.Signature, in.InputPEM, in.OutputPEM)
		if rerr != nil {
			return ArchiveOutput{}, &Error{Kind: KindInvalid, Op: op, err: rerr}
		}
		out.Signature = reencoded
	}
	return out, nil
}

// revokedSigners names the signers whose certificates came back revoked.
func revokedSigners(signers []Signer) []string {
	var out []string
	for i, sig := range signers {
		if sig.Revocation != nil && sig.Revocation.Determinate && sig.Revocation.Revoked {
			name := sig.Certificate.Subject.CommonName
			if name == "" {
				name = fmt.Sprintf("signer[%d]", i)
			}
			out = append(out, name)
		}
	}
	return out
}

// embedEvidence writes the collected evidence into the container's unsigned
// attributes. It refuses an archive with nothing in it rather than reporting
// success over an empty envelope.
func embedEvidence(signature []byte, inputPEM, outputPEM bool, evidence cms.Evidence) (ArchiveOutput, error) {
	if evidence.Empty() {
		return ArchiveOutput{}, errors.New("no long-term validation evidence could be collected (responder unreachable, or nothing to embed)")
	}
	der := signature
	if inputPEM {
		block, _ := pem.Decode(signature)
		if block == nil {
			return ArchiveOutput{}, errors.New("signature is not valid PEM")
		}
		der = block.Bytes
	}
	archived, err := cms.AddLTV(der, evidence)
	if err != nil {
		return ArchiveOutput{}, err
	}
	out := ArchiveOutput{
		Signature: archived,
		Level:     "LT",
		Embedded: ArchiveEvidence{
			OCSPResponses: len(evidence.OCSPResponses),
			CRLs:          len(evidence.CRLs),
			Certificates:  len(evidence.Certificates),
		},
	}
	if outputPEM {
		out.Signature = pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: archived})
	}
	return out, nil
}

// reencodeCMS converts a container between PEM and DER.
func reencodeCMS(sig []byte, fromPEM, toPEM bool) ([]byte, error) {
	if fromPEM == toPEM {
		return sig, nil
	}
	if toPEM {
		return pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: sig}), nil
	}
	block, _ := pem.Decode(sig)
	if block == nil {
		return nil, errors.New("archived container is not valid PEM")
	}
	return block.Bytes, nil
}

// ArchivedEvidence reports the long-term validation material already embedded in
// a container, so a caller can tell an archived signature from a plain one.
func (s *Service) ArchivedEvidence(signature []byte, inputPEM bool) (ArchiveEvidence, error) {
	der := signature
	if inputPEM {
		block, _ := pem.Decode(signature)
		if block == nil {
			return ArchiveEvidence{}, &Error{Kind: KindInvalid, Op: "ArchivedEvidence",
				err: errors.New("signature is not valid PEM")}
		}
		der = block.Bytes
	}
	ev, err := cms.EmbeddedEvidence(der)
	if err != nil {
		return ArchiveEvidence{}, &Error{Kind: KindInvalid, Op: "ArchivedEvidence", err: err}
	}
	return ArchiveEvidence{
		OCSPResponses: len(ev.OCSPResponses),
		CRLs:          len(ev.CRLs),
		Certificates:  len(ev.Certificates),
	}, nil
}
