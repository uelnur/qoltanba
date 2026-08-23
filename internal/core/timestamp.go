package core

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
	"github.com/deatil/go-cryptobin/hash/gost/gost34112012512"

	"github.com/uelnur/qoltanba/internal/cms"
	"github.com/uelnur/qoltanba/internal/pki"
	"github.com/uelnur/qoltanba/internal/provider"
)

// Verifying a timestamp token, as opposed to reading it.
//
// A TSP token in a signature is just an attribute: anyone can move one from one
// container to another, and a parser that only reads its genTime cannot tell the
// difference. RFC 3161 binds the token to what it stamps through the message
// imprint — the digest of the signer's signature value — so recomputing that
// digest and comparing is what turns "a timestamp is attached" into "this
// timestamp is over this signature", which is what CAdES-T claims.
//
// Two independent facts have to hold, and they fail differently:
//
//   - the imprint binds the token to this signature — otherwise a token lifted
//     from another container reads exactly the same;
//   - the TSA actually signed the token — otherwise the imprint only says someone
//     built a structure naming this signature.
//
// CAdES-T is claimed only when both hold. A TimeStampToken is itself a CMS
// SignedData, so the second check is the ordinary CMS verify pointed at the token
// rather than a second signature implementation.

// verifyTimestampImprint recomputes the token's message imprint from the signer's
// signature value and reports whether it matches. A nil result means the check
// could not be performed; the note says why, so the difference between "does not
// match" and "could not tell" survives into the output.
func (s *Service) verifyTimestampImprint(ctx context.Context, si cms.SignerInfo) (*bool, string) {
	ts := si.Timestamp
	switch {
	case ts == nil:
		return nil, "no timestamp token"
	case len(ts.Hash) == 0:
		return nil, "the token carries no message imprint"
	case len(si.Signature) == 0:
		return nil, "the signature value could not be read from the container"
	}
	digest, err := s.digestFor(ctx, ts.HashAlgorithmOID, si.Signature)
	if err != nil {
		return nil, err.Error()
	}
	match := bytes.Equal(digest, ts.Hash)
	if !match {
		return &match, "the token's message imprint does not match this signature"
	}
	return &match, ""
}

// digestFor hashes data with the algorithm named by OID. SHA family digests are
// computed in Go so the check works without the native library; GOST goes through
// the driver, which is the only thing here that can compute it.
//
// For any GOST profile the TSP request imprint uses the older GOST 34.311-95 —
// there is no 2015 branch for TSP — so a GOST-2015 signature still stamps with a
// digest the driver supports.
func (s *Service) digestFor(ctx context.Context, oid string, data []byte) ([]byte, error) {
	switch oid {
	case pki.DigestSHA1:
		sum := sha1.Sum(data) //nolint:gosec // the token names the algorithm; we only reproduce it
		return sum[:], nil
	case pki.DigestSHA256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case oidSHA384:
		sum := sha512.Sum384(data)
		return sum[:], nil
	case oidSHA512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	// GOST R 34.11-2015 is the Kazakh adoption of Streebog (GOST R 34.11-2012), and
	// it is what a real NUC TSA writes into the imprint under the default
	// GOST2015 policy. Kalkan cannot compute it — HashData in 2.0.13 exposes only
	// SHA-256 and the 1994/95 GOST, and answers every 2015 spelling with
	// "unknown algorithm" — so this one digest comes from Go. It is a hash used to
	// compare against a value, never a signature check: the crypto verdicts still
	// belong to the library.
	switch oid {
	case pki.OIDDigestGOST2015_512:
		return streebog(gost34112012512.New(), data), nil
	case pki.OIDDigestGOST2015_256:
		return streebog(gost34112012256.New(), data), nil
	}
	// The 1994/95 GOST has no Go implementation here, so it goes to the driver.
	if oid != pki.DigestGOST34311_95 && oid != oidGOST34311 && oid != pki.OIDDigestGOST34311_95 {
		return nil, fmt.Errorf("unsupported imprint digest %s", oid)
	}
	if !s.prov.Capabilities().Hash {
		return nil, fmt.Errorf("the loaded library cannot compute %s", gostDigestName)
	}
	res, err := s.prov.Hash(ctx, provider.HashRequest{Algorithm: gostDigestName, Data: data})
	if err != nil {
		return nil, fmt.Errorf("could not compute the %s imprint: %w", gostDigestName, err)
	}
	return res.Hash, nil
}

// streebog runs data through a Streebog digest.
func streebog(h hash.Hash, data []byte) []byte {
	h.Write(data)
	return h.Sum(nil)
}

// Digest OIDs the SHA path covers beyond the two named in pki, the second GOST
// 34.311-95 spelling, and the driver's name for that digest.
const (
	oidSHA384      = "2.16.840.1.101.3.4.2.2"
	oidSHA512      = "2.16.840.1.101.3.4.2.3"
	oidGOST34311   = "1.2.398.3.10.1.1.1"
	gostDigestName = "GOST34311"
)

// verifyTimestampSignature checks the TSA's own signature over the token. The
// certificate-time gate is deliberately off: a timestamp is supposed to outlive
// the TSA certificate that made it, and refusing an old token because its issuer
// has since expired would defeat what timestamping is for. What this establishes
// is that the token is genuine and chains to a trusted anchor, not that it was
// made while the TSA certificate was current.
func (s *Service) verifyTimestampSignature(ctx context.Context, ts *cms.Timestamp, trusted []TrustedCert) (*bool, string) {
	if ts == nil || len(ts.Raw) == 0 {
		return nil, "the token bytes were not retained"
	}
	res, err := s.prov.VerifyCMS(ctx, provider.VerifyRequest{
		Signature:     ts.Raw,
		CheckCertTime: false,
		TrustedCerts:  toProviderCerts(trusted),
	})
	switch {
	case err == nil:
		valid := res.Valid
		if !valid {
			return &valid, "the TSA signature over the token did not verify"
		}
		return &valid, ""
	case isSoftVerifyFailure(err):
		// The library reached a verdict and it was negative — that is an answer.
		no := false
		return &no, "the TSA signature over the token did not verify: " + ExplainIn(ctx, err).Message
	default:
		return nil, "the TSA signature could not be checked: " + err.Error()
	}
}
