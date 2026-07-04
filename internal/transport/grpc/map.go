package grpc

import (
	"time"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
)

// ── request: proto → core ──

func pbFormat(f pb.SignatureFormat) core.SignatureFormat {
	switch f {
	case pb.SignatureFormat_CMS:
		return core.FormatCMS
	case pb.SignatureFormat_XML:
		return core.FormatXML
	case pb.SignatureFormat_WSSE:
		return core.FormatWSSE
	default:
		return ""
	}
}

func pbEncoding(e pb.CertEncoding) core.CertEncoding {
	switch e {
	case pb.CertEncoding_DER:
		return core.EncodingDER
	case pb.CertEncoding_BASE64:
		return core.EncodingB64
	default:
		return core.EncodingPEM
	}
}

func pbMethod(m pb.ValidationMethod) core.ValidationMethod {
	if m == pb.ValidationMethod_CRL {
		return core.MethodCRL
	}
	return core.MethodOCSP
}

func pbKeySpec(k *pb.KeySpec) core.KeySpec {
	if k == nil {
		return core.KeySpec{}
	}
	switch src := k.Source.(type) {
	case *pb.KeySpec_Inline:
		return core.KeySpec{Inline: &core.InlineKey{P12: src.Inline.GetP12(), Password: src.Inline.GetPassword(), Alias: src.Inline.GetAlias()}}
	case *pb.KeySpec_Path:
		return core.KeySpec{Path: &core.PathKey{Path: src.Path.GetPath(), Password: src.Path.GetPassword(), Alias: src.Path.GetAlias()}}
	case *pb.KeySpec_Token:
		return core.KeySpec{Token: &core.TokenKey{Storage: src.Token.GetStorage(), PIN: src.Token.GetPin(), Alias: src.Token.GetAlias()}}
	case *pb.KeySpec_KeyId:
		return core.KeySpec{KeyID: src.KeyId}
	default:
		return core.KeySpec{}
	}
}

func pbTrusted(in []*pb.TrustedCert) []core.TrustedCert {
	if len(in) == 0 {
		return nil
	}
	out := make([]core.TrustedCert, 0, len(in))
	for _, c := range in {
		out = append(out, core.TrustedCert{Cert: c.GetCert(), Intermediate: c.GetIntermediate()})
	}
	return out
}

// ── response: core → proto ──

func coreFormatPB(f core.SignatureFormat) pb.SignatureFormat {
	switch f {
	case core.FormatCMS:
		return pb.SignatureFormat_CMS
	case core.FormatXML:
		return pb.SignatureFormat_XML
	case core.FormatWSSE:
		return pb.SignatureFormat_WSSE
	default:
		return pb.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED
	}
}

func coreMethodPB(m core.ValidationMethod) pb.ValidationMethod {
	if m == core.MethodCRL {
		return pb.ValidationMethod_CRL
	}
	if m == core.MethodOCSP {
		return pb.ValidationMethod_OCSP
	}
	return pb.ValidationMethod_VALIDATION_METHOD_UNSPECIFIED
}

func libErrorPB(e *core.LibError) *pb.LibError {
	if e == nil {
		return nil
	}
	return &pb.LibError{Code: e.Code, Text: e.Text}
}

func warningsPB(ws []core.Warning) []*pb.Warning {
	if len(ws) == 0 {
		return nil
	}
	out := make([]*pb.Warning, 0, len(ws))
	for _, w := range ws {
		out = append(out, &pb.Warning{Field: w.Field, Reason: w.Reason})
	}
	return out
}

func rfc3339(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func subjectPB(s core.Subject) *pb.Subject {
	return &pb.Subject{
		CommonName: s.CommonName, LastName: s.LastName, GivenName: s.GivenName, Email: s.Email,
		Organization: s.Organization, OrgUnit: s.OrgUnit, Country: s.Country, Locality: s.Locality,
		State: s.State, BusinessCategory: s.BusinessCategory, DomainComponent: s.DomainComponent, Dn: s.DN,
		Iin: s.IIN, Bin: s.BIN, Gender: s.Gender,
	}
}

func certPB(c core.Certificate) *pb.Certificate {
	return &pb.Certificate{
		Subject: subjectPB(c.Subject), Issuer: subjectPB(c.Issuer),
		SerialNumber: c.SerialNumber, NotBefore: rfc3339(c.NotBefore), NotAfter: rfc3339(c.NotAfter),
		SignatureAlgorithm: c.SignatureAlgorithm, SignatureAlgorithmOid: c.SignatureAlgorithmOID,
		KeyAlgorithm: c.KeyAlgorithm, PublicKey: c.PublicKey,
		AuthorityKeyId: c.AuthorityKeyID, SubjectKeyId: c.SubjectKeyID,
		KeyUsage: c.KeyUsage, KeyUsageKind: c.KeyUsageKind, ExtendedKeyUsage: c.ExtendedKeyUsage,
		PolicyOids: c.PolicyOIDs, OwnerType: c.OwnerType, Roles: c.Roles,
		CaIssuerUrls: c.CAIssuerURLs, OcspUrls: c.OCSPURLs, CrlUrls: c.CRLURLs,
		IsCa: c.IsCA, Pem: c.PEM,
	}
}

func certsPB(cs []core.Certificate) []*pb.Certificate {
	if len(cs) == 0 {
		return nil
	}
	out := make([]*pb.Certificate, 0, len(cs))
	for _, c := range cs {
		out = append(out, certPB(c))
	}
	return out
}

func timestampPB(t *core.Timestamp) *pb.Timestamp {
	if t == nil {
		return nil
	}
	return &pb.Timestamp{
		SerialNumber: t.SerialNumber, GenTime: rfc3339(t.GenTime), Policy: t.Policy,
		Tsa: t.TSA, HashAlgorithm: t.HashAlgorithm, Hash: t.Hash,
	}
}

func signerPB(s core.Signer) *pb.Signer {
	return &pb.Signer{
		Certificate: certPB(s.Certificate), Chain: certsPB(s.Chain), Valid: s.Valid,
		SigningTime: rfc3339(s.SigningTime), SignatureAlgorithm: s.SignatureAlgorithm,
		Timestamp: timestampPB(s.Timestamp), ChainComplete: s.ChainComplete,
		TrustAnchorFound: s.TrustAnchorFound, ChainSignaturesVerified: s.ChainSignaturesVerified,
		CadesLevel: s.CAdESLevel, VerifyInfo: s.VerifyInfo,
	}
}

func signersPB(ss []core.Signer) []*pb.Signer {
	if len(ss) == 0 {
		return nil
	}
	out := make([]*pb.Signer, 0, len(ss))
	for _, s := range ss {
		out = append(out, signerPB(s))
	}
	return out
}

func revocationPB(r core.RevocationStatus) *pb.RevocationStatus {
	return &pb.RevocationStatus{
		Revoked: r.Revoked, Method: coreMethodPB(r.Method), RevocationTime: rfc3339(r.RevocationTime),
		Reason: r.Reason, CheckedAt: rfc3339(r.CheckedAt), LibError: libErrorPB(r.LibError),
		ThisUpdate: rfc3339(r.ThisUpdate), NextUpdate: rfc3339(r.NextUpdate), ProducedAt: rfc3339(r.ProducedAt),
	}
}
