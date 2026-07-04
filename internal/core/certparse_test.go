package core

import "testing"

func TestParseCertificate_IndividualDerivation(t *testing.T) {
	var w warnings
	// Male IIN: 7th digit is odd (…S… = 3). No OU → individual.
	props := fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТОВ ТЕСТ",
		"SUBJECT_SURNAME":      "ТЕСТОВ",
		"SUBJECT_GIVENNAME":    "ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN900130300123",
		"SUBJECT_COUNTRYNAME":  "KZ",
		"NOTBEFORE":            "08.05.2026 06:45:13 +00:00",
		"NOTAFTER":             "08.05.2027 06:45:13 +00:00",
		"KEY_USAGE":            "digitalSignature nonRepudiation keyAgreement",
		"EXT_KEY_USAGE":        "E-mail Protection (1.3.6.1.5.5.7.3.4); 1.2.398.3.3.4.1.1 (Физическое лицо)",
		"SIGNATURE_ALG":        "GOST R 34.10-2015 (1.2.398.3.10.1.1.2.3.1)",
		"CERT_SN":              "6C4256AB",
	})

	c := parseCertificate(props, nil, "", &w)

	if c.Subject.IIN != "900130300123" {
		t.Errorf("IIN = %q, want 900130300123", c.Subject.IIN)
	}
	if c.Subject.Gender != "MALE" {
		t.Errorf("Gender = %q, want MALE", c.Subject.Gender)
	}
	if c.OwnerType != "INDIVIDUAL" {
		t.Errorf("OwnerType = %q, want INDIVIDUAL", c.OwnerType)
	}
	if c.KeyUsageKind != "SIGN" {
		t.Errorf("KeyUsageKind = %q, want SIGN", c.KeyUsageKind)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "INDIVIDUAL" {
		t.Errorf("Roles = %v, want [INDIVIDUAL]", c.Roles)
	}
	if c.SignatureAlgorithmOID != "1.2.398.3.10.1.1.2.3.1" {
		t.Errorf("SignatureAlgorithmOID = %q", c.SignatureAlgorithmOID)
	}
	if c.KeyAlgorithm != "gost2015-256" {
		t.Errorf("KeyAlgorithm = %q, want gost2015-256", c.KeyAlgorithm)
	}
	if c.NotBefore == nil || c.NotBefore.Year() != 2026 || c.NotBefore.Month() != 5 {
		t.Errorf("NotBefore = %v, want 2026-05", c.NotBefore)
	}
	if len(w.list()) != 0 {
		t.Errorf("unexpected warnings: %v", w.list())
	}
}

func TestParseCertificate_LegalPersonAndInfosystem(t *testing.T) {
	var w warnings
	legal := parseCertificate(fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ИВАНОВ ИВАН",
		"SUBJECT_SERIALNUMBER": "IIN800101400555", // 7th digit 4 → female
		"SUBJECT_ORGUNIT_NAME": "BIN123456789021",
		"SUBJECT_ORG_NAME":     "АО ТЕСТ",
	}), nil, "", &w)
	if legal.Subject.BIN != "123456789021" {
		t.Errorf("legal BIN = %q", legal.Subject.BIN)
	}
	if legal.Subject.Gender != "FEMALE" {
		t.Errorf("legal Gender = %q, want FEMALE", legal.Subject.Gender)
	}
	if legal.OwnerType != "LEGAL_PERSON" {
		t.Errorf("legal OwnerType = %q, want LEGAL_PERSON", legal.OwnerType)
	}

	info := parseCertificate(fields(map[string]string{
		"SUBJECT_ORGUNIT_NAME": "BIN123456789021",
		"SUBJECT_ORG_NAME":     "АО ТЕСТ",
	}), nil, "", &w)
	if info.OwnerType != "INFOSYSTEM" {
		t.Errorf("info OwnerType = %q, want INFOSYSTEM", info.OwnerType)
	}
}

func TestParseCertificate_CAmarkers(t *testing.T) {
	var w warnings
	ca := parseCertificate(fields(map[string]string{
		"KEY_USAGE": "keyCertSign cRLSign",
	}), nil, "", &w)
	if !ca.IsCA {
		t.Error("expected IsCA for keyCertSign without EKU")
	}

	leaf := parseCertificate(fields(map[string]string{
		"KEY_USAGE":     "keyCertSign", // present, but EKU makes it a leaf
		"EXT_KEY_USAGE": "1.2.398.3.3.4.1.1 (Физическое лицо)",
	}), nil, "", &w)
	if leaf.IsCA {
		t.Error("expected non-CA when EKU is present")
	}
}

func TestParseCertificate_BadTimeWarns(t *testing.T) {
	var w warnings
	parseCertificate(fields(map[string]string{"NOTBEFORE": "not-a-date"}), nil, "", &w)
	if len(w.list()) != 1 || w.list()[0].Field != "notBefore" {
		t.Errorf("warnings = %v, want one for notBefore", w.list())
	}
}
