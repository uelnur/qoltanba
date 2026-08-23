package core

import "fmt"

// SignaturePolicy is a named signing profile. It exists so a caller states the
// interoperability level they need — "CAdES-T" — instead of assembling the flags
// that happen to produce it, which is both easier to get wrong and harder to read
// in a review.
//
// The levels follow ETSI: B (baseline, formerly BES) is a plain signature; T adds
// a trusted time-stamp token. LT/LTA (embedded revocation evidence, archival
// time-stamps) are not offered yet — they need long-term validation material,
// which is a separate piece of work, and naming them here before they exist would
// promise interoperability the service cannot deliver.
type SignaturePolicy string

const (
	PolicyCAdESB SignaturePolicy = "cades-b" // CMS/PKCS#7 baseline
	PolicyCAdEST SignaturePolicy = "cades-t" // CMS + TSA time-stamp
	PolicyXAdESB SignaturePolicy = "xades-b" // XMLDSig baseline
	PolicyXAdEST SignaturePolicy = "xades-t" // XMLDSig + TSA time-stamp
)

// policyProfile is what a policy resolves to.
type policyProfile struct {
	format    SignatureFormat
	timestamp bool
}

var policyProfiles = map[SignaturePolicy]policyProfile{
	PolicyCAdESB: {format: FormatCMS, timestamp: false},
	PolicyCAdEST: {format: FormatCMS, timestamp: true},
	PolicyXAdESB: {format: FormatXML, timestamp: false},
	PolicyXAdEST: {format: FormatXML, timestamp: true},
}

// Valid reports whether p is a known policy.
func (p SignaturePolicy) Valid() bool {
	_, ok := policyProfiles[p]
	return ok
}

// Policies lists the supported policies, for error messages and discovery.
func Policies() []SignaturePolicy {
	return []SignaturePolicy{PolicyCAdESB, PolicyCAdEST, PolicyXAdESB, PolicyXAdEST}
}

// applyPolicy resolves the named profile into the request. An explicit format
// that contradicts the policy is an error rather than a silent override: the
// caller stated two different intents and only they can say which one is right.
// An explicit withTimestamp is likewise honored — it is a deliberate override of
// the level's default, which the resulting cadesLevel will reflect.
func applyPolicy(in *SignInput) error {
	if in.Policy == "" {
		return nil
	}
	profile, ok := policyProfiles[in.Policy]
	if !ok {
		return fmt.Errorf("unknown signature policy %q (supported: %s)", in.Policy, policyList())
	}
	if in.Format != "" && in.Format != profile.format {
		return fmt.Errorf("policy %q signs %s, but the request asks for %s",
			in.Policy, profile.format, in.Format)
	}
	in.Format = profile.format
	if in.WithTimestamp == nil {
		ts := profile.timestamp
		in.WithTimestamp = &ts
	}
	return nil
}

func policyList() string {
	out := ""
	for i, p := range Policies() {
		if i > 0 {
			out += ", "
		}
		out += string(p)
	}
	return out
}
