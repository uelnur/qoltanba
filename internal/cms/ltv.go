package cms

import (
	"encoding/asn1"
	"fmt"
)

// Long-term validation: embedding the evidence a signature needs to stay
// checkable after its certificate expires and after the CA's responders go away.
//
// A signature verifies today because an OCSP responder answers today. In five
// years that responder may be gone, the certificate long expired, and the
// signature — still mathematically sound — unverifiable in practice. CAdES solves
// this by carrying the evidence inside the container: the OCSP responses and CRLs
// that were valid at signing time, plus the certificates of the chain.
//
// The evidence goes into *unsigned* attributes, which is what makes adding it to
// an already-signed container legitimate: they are outside the signature, so the
// signature stays intact. Everything else in the container is rewritten
// byte-for-byte from the original — parsing and re-encoding the signed parts would
// risk changing their DER and invalidating the very signature being preserved.
//
// This produces CAdES-LT (evidence embedded). LTA — an archive timestamp over the
// whole structure — is not produced here: it needs a fresh TSA round trip over the
// completed container, which is a separate operation rather than a repackaging.

// LTV attribute OIDs (ETSI EN 319 122 / RFC 5126).
var (
	oidRevocationValues  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}
	oidCertificateValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}
)

// Evidence is the long-term validation material to embed.
type Evidence struct {
	// OCSPResponses are complete DER OCSPResponse structures, as returned by a
	// responder.
	OCSPResponses [][]byte
	// CRLs are DER CertificateList structures.
	CRLs [][]byte
	// Certificates are DER certificates of the chain (issuers, responder certs)
	// that a future verifier will not be able to fetch.
	Certificates [][]byte
}

// Empty reports whether there is nothing to embed.
func (e Evidence) Empty() bool {
	return len(e.OCSPResponses) == 0 && len(e.CRLs) == 0 && len(e.Certificates) == 0
}

// AddLTV returns the CMS container with the evidence added to every signer's
// unsigned attributes. The input must be DER (strip the PEM envelope first).
//
// It refuses rather than guesses when the container is not a SignedData, and it
// leaves an already-annotated signer alone: replacing evidence somebody else
// embedded would discard information, and duplicating it would produce an
// attribute a verifier may reject.
func AddLTV(der []byte, ev Evidence) ([]byte, error) {
	if ev.Empty() {
		return nil, fmt.Errorf("cms: no long-term validation evidence to embed")
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: parse container: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("cms: not a SignedData container")
	}

	// The SignedData body is rebuilt from its own original elements: every field
	// but the signer set is copied verbatim. Re-encoding parsed fields would risk
	// changing their DER — and the signature covers some of them.
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("cms: parse SignedData: %w", err)
	}
	elements := splitDER(sd.Bytes)
	if len(elements) < 4 {
		return nil, fmt.Errorf("cms: SignedData has %d elements, expected at least 4", len(elements))
	}
	// SignerInfos is the last element of SignedData (RFC 5652).
	signerSetRaw := elements[len(elements)-1]
	prefix := sd.Bytes[:len(sd.Bytes)-len(signerSetRaw)]

	var signerSet asn1.RawValue
	if _, err := asn1.Unmarshal(signerSetRaw, &signerSet); err != nil {
		return nil, fmt.Errorf("cms: parse signers: %w", err)
	}
	signers := splitDER(signerSet.Bytes)
	if len(signers) == 0 {
		return nil, fmt.Errorf("cms: container carries no signers")
	}

	attrs, err := evidenceAttributes(ev)
	if err != nil {
		return nil, err
	}

	var rebuilt []byte
	for _, si := range signers {
		updated, err := signerWithEvidence(si, attrs)
		if err != nil {
			return nil, err
		}
		rebuilt = append(rebuilt, updated...)
	}

	newSet := encodeRaw(asn1.ClassUniversal, asn1.TagSet, true, rebuilt)
	newBody := append(append([]byte{}, prefix...), newSet...)
	newSD := encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true, newBody)

	// The ContentInfo is assembled by hand for the same reason as the body: the
	// SignedData is wrapped in an explicit [0], and handing pre-encoded bytes to
	// the struct marshaller would drop that wrapper.
	oid, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, fmt.Errorf("cms: encode content type: %w", err)
	}
	content := encodeRaw(asn1.ClassContextSpecific, 0, true, newSD)
	return encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true,
		append(append([]byte{}, oid...), content...)), nil
}

// signerWithEvidence rebuilds one SignerInfo with the evidence appended to its
// unsigned attributes, copying every other element verbatim.
func signerWithEvidence(siRaw []byte, attrs []attribute) ([]byte, error) {
	var si asn1.RawValue
	if _, err := asn1.Unmarshal(siRaw, &si); err != nil {
		return nil, fmt.Errorf("cms: parse signer: %w", err)
	}
	elements := splitDER(si.Bytes)
	if len(elements) < 5 {
		return nil, fmt.Errorf("cms: SignerInfo has %d elements, expected at least 5", len(elements))
	}

	// unsignedAttrs is the optional [1] element, and it can only be the last one.
	var existing []attribute
	body := si.Bytes
	if last := elements[len(elements)-1]; isContextTag(last, 1) {
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(last, &raw); err != nil {
			return nil, fmt.Errorf("cms: parse unsigned attributes: %w", err)
		}
		parsed, err := parseAttributeList(raw.Bytes)
		if err != nil {
			return nil, err
		}
		existing = parsed
		body = si.Bytes[:len(si.Bytes)-len(last)]
	}

	for _, a := range attrs {
		if hasAttribute(existing, a.Type) {
			// Already annotated: keep what is there rather than duplicating an
			// attribute or discarding someone else's evidence.
			continue
		}
		existing = append(existing, a)
	}

	encoded := make([][]byte, 0, len(existing))
	for _, a := range existing {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("cms: encode unsigned attribute: %w", err)
		}
		encoded = append(encoded, b)
	}
	// Context tag 1, implicit over a SET OF Attribute.
	newAttrs := encodeRaw(asn1.ClassContextSpecific, 1, true, concat(encoded))
	return encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true,
		append(append([]byte{}, body...), newAttrs...)), nil
}

// isContextTag reports whether a DER element carries the given context-specific
// tag. Only the low tag numbers CMS uses are considered, which keeps this to the
// single identifier byte.
func isContextTag(der []byte, tag byte) bool {
	if len(der) == 0 {
		return false
	}
	const contextConstructed = 0xA0
	return der[0] == contextConstructed|tag
}

func parseAttributeList(b []byte) ([]attribute, error) {
	var attrs []attribute
	rest := b
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, fmt.Errorf("cms: parse attribute: %w", err)
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// encodeRaw builds a DER element with the given identifier over body.
func encodeRaw(class, tag int, compound bool, body []byte) []byte {
	out, err := asn1.Marshal(asn1.RawValue{
		Class: class, Tag: tag, IsCompound: compound, Bytes: body,
	})
	if err != nil {
		// RawValue with explicit class/tag/bytes cannot fail to marshal; a failure
		// here would mean the caller handed in something impossible.
		return nil
	}
	return out
}

func concat(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// revocationValues is the ETSI RevocationValues attribute value: CRLs under an
// explicit [0], OCSP responses under an explicit [1].
type revocationValues struct {
	CRLValues  asn1.RawValue `asn1:"optional,explicit,tag:0"`
	OCSPValues asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

// evidenceAttributes builds the attributes to append.
//
// The DER here is assembled explicitly rather than by tagging struct fields:
// asn1.Marshal writes a RawValue exactly as given and ignores the field's tag, so
// a "explicit,tag:1" annotation on a RawValue silently produces an untagged
// element — which parses as something else entirely.
func evidenceAttributes(ev Evidence) ([]attribute, error) {
	var attrs []attribute

	if len(ev.OCSPResponses) > 0 || len(ev.CRLs) > 0 {
		var body []byte
		if len(ev.CRLs) > 0 {
			seq := encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true, concat(ev.CRLs))
			body = append(body, encodeRaw(asn1.ClassContextSpecific, 0, true, seq)...)
		}
		if len(ev.OCSPResponses) > 0 {
			// The OCSP values are the responder's own DER responses; a future
			// verifier reads them exactly as it would read a live answer.
			seq := encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true, concat(ev.OCSPResponses))
			body = append(body, encodeRaw(asn1.ClassContextSpecific, 1, true, seq)...)
		}
		value := encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true, body)
		attrs = append(attrs, attribute{
			Type:   oidRevocationValues,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: value},
		})
	}

	if len(ev.Certificates) > 0 {
		seq := encodeRaw(asn1.ClassUniversal, asn1.TagSequence, true, concat(ev.Certificates))
		attrs = append(attrs, attribute{
			Type:   oidCertificateValues,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: seq},
		})
	}

	return attrs, nil
}

func hasAttribute(attrs []attribute, oid asn1.ObjectIdentifier) bool {
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			return true
		}
	}
	return false
}

// EmbeddedEvidence reads back the long-term validation material embedded in a
// container, so a verifier can use it instead of reaching a responder that may no
// longer exist.
func EmbeddedEvidence(der []byte) (Evidence, error) {
	var ev Evidence

	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return ev, fmt.Errorf("cms: parse container: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return ev, fmt.Errorf("cms: not a SignedData container")
	}
	var sd signedDataRaw
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return ev, fmt.Errorf("cms: parse SignedData: %w", err)
	}

	for _, si := range sd.SignerInfos {
		if len(si.UnsignedAttrs.Bytes) == 0 {
			continue
		}
		attrs, err := parseAttributeList(si.UnsignedAttrs.Bytes)
		if err != nil {
			return ev, err
		}
		for _, a := range attrs {
			switch {
			case a.Type.Equal(oidRevocationValues):
				var rv revocationValues
				if _, err := asn1.Unmarshal(a.Values.Bytes, &rv); err != nil {
					continue // a malformed attribute is not worth failing the read over
				}
				// Each field is an explicit tag over a SEQUENCE OF, so the elements
				// are one level further in than the tag's own content.
				ev.CRLs = append(ev.CRLs, sequenceElements(rv.CRLValues.Bytes)...)
				ev.OCSPResponses = append(ev.OCSPResponses, sequenceElements(rv.OCSPValues.Bytes)...)
			case a.Type.Equal(oidCertificateValues):
				ev.Certificates = append(ev.Certificates, sequenceElements(a.Values.Bytes)...)
			}
		}
	}
	return ev, nil
}

// sequenceElements unwraps a SEQUENCE and returns its elements. An input that is
// not a sequence yields nothing rather than a misread element.
func sequenceElements(der []byte) [][]byte {
	if len(der) == 0 {
		return nil
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil
	}
	if seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil
	}
	return splitDER(seq.Bytes)
}

// splitDER walks concatenated DER elements and returns each one's full bytes.
func splitDER(b []byte) [][]byte {
	var out [][]byte
	rest := b
	for len(rest) > 0 {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			return out
		}
		out = append(out, v.FullBytes)
		rest = next
	}
	return out
}
