package grpc

import (
	"time"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
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

func signInputPB(req *pb.SignRequest) core.SignInput {
	return core.SignInput{
		Format: pbFormat(req.GetFormat()), Data: req.GetData(), Key: pbKeySpec(req.GetKey()),
		DataRef:  core.DataRef{Path: req.GetDataPath(), URL: req.GetDataUrl()},
		Detached: req.GetDetached(), WithTimestamp: req.WithTimestamp, TSAURL: req.GetTsaUrl(),
		NoCheckCertTime: req.GetNoCheckCertTime(), InputPEM: req.GetInputPem(), OutputPEM: req.GetOutputPem(),
		NodeID: req.GetNodeId(), ParentNode: req.GetParentNode(), ParentNS: req.GetParentNamespace(),
		ExistingSignature: req.GetExistingSignature(),
	}
}

func verifyInputPB(req *pb.VerifyRequest) core.VerifyInput {
	return core.VerifyInput{
		Format: pbFormat(req.GetFormat()), Signature: req.GetSignature(), Data: req.GetData(),
		DataRef:  core.DataRef{Path: req.GetDataPath(), URL: req.GetDataUrl()},
		Detached: req.GetDetached(), InputPEM: req.GetInputPem(), CheckCertTime: req.GetCheckCertTime(),
		ExtractContent: req.GetExtractContent(), ExtractClaims: req.GetClaims(),
		TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	}
}

func extractInputPB(req *pb.ExtractRequest) core.ExtractInput {
	return core.ExtractInput{Format: pbFormat(req.GetFormat()), Signature: req.GetSignature(), Data: req.GetData()}
}

func certInfoInputPB(req *pb.CertInfoRequest) core.CertInfoInput {
	return core.CertInfoInput{
		Cert: req.GetCert(), Key: pbKeySpec(req.GetKey()), Format: pbEncoding(req.GetEncoding()),
		BuildChain: req.GetBuildChain(), Validate: req.GetValidate(), ExtractClaims: req.GetClaims(),
		Method: pbMethod(req.GetMethod()), TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	}
}

func validateInputPB(req *pb.CertValidateRequest) core.ValidateInput {
	return core.ValidateInput{
		Cert: req.GetCert(), Format: pbEncoding(req.GetEncoding()), Method: pbMethod(req.GetMethod()),
		WantOCSP: req.GetWantOcsp(), ResponderURL: req.GetResponderUrl(), CRL: req.GetCrl(),
		TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	}
}

// ── response: core → proto ──

// The response builders take a pointer so the batch handlers can pass a possibly
// nil per-item output (a failed item has none); the single-call handlers pass the
// address of their value result.

func signResponsePB(o *core.SignOutput) *pb.SignResponse {
	if o == nil {
		return nil
	}
	return &pb.SignResponse{
		Signature: o.Signature, Format: coreFormatPB(o.Format),
		Timestamp: timestampPB(o.Timestamp), CadesLevel: o.CAdESLevel, LibError: libErrorPB(o.LibError),
	}
}

func verifyResponsePB(o *core.VerifyOutput) *pb.VerifyResponse {
	if o == nil {
		return nil
	}
	return &pb.VerifyResponse{
		Valid: o.Valid, Format: coreFormatPB(o.Format), Detached: o.Detached,
		Signers: signersPB(o.Signers), Content: o.Content,
		Warnings: warningsPB(o.Warnings), LibError: libErrorPB(o.LibError),
	}
}

func extractResponsePB(o *core.ExtractOutput) *pb.ExtractResponse {
	if o == nil {
		return nil
	}
	return &pb.ExtractResponse{Content: o.Content, Detached: o.Detached, LibError: libErrorPB(o.LibError)}
}

func certInfoResponsePB(o *core.CertInfoOutput) *pb.CertInfoResponse {
	if o == nil {
		return nil
	}
	return &pb.CertInfoResponse{
		Certificate: certPB(o.Certificate), Chain: certsPB(o.Chain),
		Warnings: warningsPB(o.Warnings), LibError: libErrorPB(o.LibError), Claims: claimsPB(o.Claims),
	}
}

func certValidateResponsePB(o *core.ValidateOutput) *pb.CertValidateResponse {
	if o == nil {
		return nil
	}
	return &pb.CertValidateResponse{
		Status: revocationPB(o.Status), Info: o.Info, OcspResponse: o.OCSPResponse,
		Warnings: warningsPB(o.Warnings), LibError: libErrorPB(o.LibError),
	}
}

// batchOptsPB maps the wire batch controls to the domain options.
func batchOptsPB(policy string, concurrency int32) core.BatchOptions {
	return core.BatchOptions{Policy: core.BatchPolicy(policy), Concurrency: int(concurrency)}
}

// batchItemErrorPB maps a per-item error (nil when the item succeeded).
func batchItemErrorPB(e *core.BatchItemError) *pb.BatchItemError {
	if e == nil {
		return nil
	}
	return &pb.BatchItemError{Kind: e.Kind, Code: e.Code, Message: e.Message, Action: e.Action}
}

// jobStatusPB maps the client-safe job view.
func jobStatusPB(v jobs.View) *pb.JobStatus {
	return &pb.JobStatus{
		Id: v.ID, Op: v.Op, Status: string(v.Status),
		SubmittedAt: rfc3339(&v.SubmittedAt), StartedAt: rfc3339(v.StartedAt),
		FinishedAt: rfc3339(v.FinishedAt), ExpiresAt: rfc3339(v.ExpiresAt),
		Error: batchItemErrorPB(v.Error),
	}
}

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
	return &pb.LibError{Code: e.Code, Text: e.Text, Key: e.Key, Message: e.Message, Action: e.Action}
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
		CadesLevel: s.CAdESLevel, VerifyInfo: s.VerifyInfo, Claims: claimsPB(s.Claims),
	}
}

// claimsPB maps the OIDC claim set (nil when not requested).
func claimsPB(c *core.Claims) *pb.Claims {
	if c == nil {
		return nil
	}
	return &pb.Claims{
		Sub: c.Sub, Name: c.Name, GivenName: c.GivenName, FamilyName: c.FamilyName,
		Email: c.Email, Iin: c.IIN, Bin: c.BIN, Organization: c.Organization,
		Roles: c.Roles, OwnerType: c.OwnerType, Gender: c.Gender,
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
