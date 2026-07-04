package core

import (
	"context"
	"reflect"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

func TestClaimsFromCertificate_Individual(t *testing.T) {
	cert := Certificate{
		Subject: Subject{
			CommonName: "ИВАНОВ ИВАН", LastName: "ИВАНОВ", GivenName: "ИВАН",
			Email: "ivan@example.kz", IIN: "900130300123", Gender: "MALE",
		},
		OwnerType: "INDIVIDUAL",
		Roles:     []string{"INDIVIDUAL"},
	}
	c := ClaimsFromCertificate(cert)
	want := Claims{
		Sub: "900130300123", Name: "ИВАНОВ ИВАН", GivenName: "ИВАН", FamilyName: "ИВАНОВ",
		Email: "ivan@example.kz", IIN: "900130300123", OwnerType: "INDIVIDUAL",
		Roles: []string{"INDIVIDUAL"}, Gender: "male",
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("claims = %+v\nwant %+v", c, want)
	}
}

func TestClaimsFromCertificate_LegalPerson(t *testing.T) {
	cert := Certificate{
		Subject: Subject{
			CommonName: "ПЕТРОВ ПЁТР", LastName: "ПЕТРОВ", GivenName: "ПЁТР",
			IIN: "800101400555", BIN: "012345678901", Organization: "ТОО Ромашка", Gender: "FEMALE",
		},
		OwnerType: "LEGAL_PERSON",
		Roles:     []string{"CEO", "CAN_SIGN"},
	}
	c := ClaimsFromCertificate(cert)
	if c.Sub != "800101400555" { // IIN preferred over BIN
		t.Errorf("sub = %q, want the IIN", c.Sub)
	}
	if c.BIN != "012345678901" || c.Organization != "ТОО Ромашка" {
		t.Errorf("bin/org = %q/%q", c.BIN, c.Organization)
	}
	if c.Gender != "female" {
		t.Errorf("gender = %q, want female", c.Gender)
	}
	if !reflect.DeepEqual(c.Roles, []string{"CEO", "CAN_SIGN"}) {
		t.Errorf("roles = %v", c.Roles)
	}
}

func TestClaimsFromCertificate_InfosystemFallsBackToBIN(t *testing.T) {
	cert := Certificate{
		Subject:   Subject{CommonName: "IS NODE", BIN: "012345678901", Gender: "NONE"},
		OwnerType: "INFOSYSTEM",
	}
	c := ClaimsFromCertificate(cert)
	if c.Sub != "012345678901" { // no IIN → BIN
		t.Errorf("sub = %q, want the BIN fallback", c.Sub)
	}
	if c.Gender != "" { // NONE is omitted
		t.Errorf("gender = %q, want empty for NONE", c.Gender)
	}
}

func TestClaimsFromCertificate_NameComposedWhenNoCN(t *testing.T) {
	c := ClaimsFromCertificate(Certificate{Subject: Subject{LastName: "ИВАНОВ", GivenName: "ИВАН"}})
	if c.Name != "ИВАНОВ ИВАН" {
		t.Errorf("name = %q, want composed", c.Name)
	}
}

func TestVerify_ExtractClaimsFlag(t *testing.T) {
	f := &fakeProvider{
		verifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		props: fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123"}),
	}
	s := newTestService(f)

	// Without the flag: no claims.
	out, _ := s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s")})
	if out.Signers[0].Claims != nil {
		t.Error("claims populated without the flag")
	}
	// With the flag: claims present and sub = IIN.
	out, _ = s.Verify(context.Background(), VerifyInput{Format: FormatCMS, Signature: []byte("s"), ExtractClaims: true})
	if out.Signers[0].Claims == nil || out.Signers[0].Claims.Sub != "900130300123" {
		t.Errorf("claims = %+v, want sub=900130300123", out.Signers[0].Claims)
	}
}

func TestCertInfo_ExtractClaimsFlag(t *testing.T) {
	f := &fakeProvider{props: fields(map[string]string{
		"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123",
	})}
	s := newTestService(f)
	out, err := s.CertInfo(context.Background(), CertInfoInput{
		Cert: []byte("cert"), Format: EncodingDER, ExtractClaims: true,
	})
	if err != nil {
		t.Fatalf("CertInfo: %v", err)
	}
	if out.Claims == nil || out.Claims.Sub != "900130300123" {
		t.Errorf("claims = %+v, want sub=900130300123", out.Claims)
	}
}
