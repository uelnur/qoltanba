package core

import "testing"

// The property maps below are captured VERBATIM from the real Kalkan driver
// (X509CertificateGetInfo, post-afterEq) for the two consumer test keys — see
// test/e2e TestFunctionalE2E_CertFieldsGolden, which asserts the live library
// still emits exactly these. This fast unit test pins the domain derivation
// (IIN/BIN, ownerType, gender, roles, key algorithm, validity) against that real
// shape without needing the native library, so a boundary regression like the
// dropped "name=" prefix surfaces in ordinary CI.

func TestParseCertificate_GoldenIndividual(t *testing.T) {
	var w warnings
	c := parseCertificate(fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТОВ ТЕСТ",
		"SUBJECT_SURNAME":      "ТЕСТОВ",
		"SUBJECT_GIVENNAME":    "ТЕСТОВИЧ",
		"SUBJECT_SERIALNUMBER": "IIN123456789011",
		"SUBJECT_COUNTRYNAME":  "KZ",
		"SUBJECT_DN":           "CN = ТЕСТОВ ТЕСТ, SN = ТЕСТОВ, serialNumber = IIN123456789011, C = KZ, GN = ТЕСТОВИЧ",
		"NOTBEFORE":            "08.05.2026 06:45:13 +00:00",
		"NOTAFTER":             "08.05.2027 06:45:13 +00:00",
		"KEY_USAGE":            "digitalSignature nonRepudiation keyAgreement ",
		"EXT_KEY_USAGE":        "E-mail Protection (1.3.6.1.5.5.7.3.4); 1.2.398.3.3.4.1.1 (1.2.398.3.3.4.1.1); ",
		"SIGNATURE_ALG":        "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)(1.2.398.3.10.1.1.2.3.2)",
		"CERT_SN":              "6C425659BD2FC6DC587B871AEDE1857727CF8451",
		"POLICIES_ID":          "1.2.398.3.3.2",
	}), nil, "", &w)

	if c.Subject.CommonName != "ТЕСТОВ ТЕСТ" {
		t.Errorf("CommonName = %q", c.Subject.CommonName)
	}
	if c.Subject.IIN != "123456789011" {
		t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
	}
	if c.Subject.BIN != "" {
		t.Errorf("BIN = %q, want empty for an individual", c.Subject.BIN)
	}
	if c.Subject.Gender != "MALE" {
		t.Errorf("Gender = %q, want MALE", c.Subject.Gender)
	}
	if c.OwnerType != "INDIVIDUAL" {
		t.Errorf("OwnerType = %q, want INDIVIDUAL", c.OwnerType)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "INDIVIDUAL" {
		t.Errorf("Roles = %v, want [INDIVIDUAL]", c.Roles)
	}
	if c.KeyAlgorithm != "gost2015-512" {
		t.Errorf("KeyAlgorithm = %q, want gost2015-512", c.KeyAlgorithm)
	}
	if c.SignatureAlgorithmOID != "1.2.398.3.10.1.1.2.3.2" {
		t.Errorf("SignatureAlgorithmOID = %q", c.SignatureAlgorithmOID)
	}
	if c.SerialNumber != "6C425659BD2FC6DC587B871AEDE1857727CF8451" {
		t.Errorf("SerialNumber = %q", c.SerialNumber)
	}
	if c.NotBefore == nil || c.NotBefore.Year() != 2026 {
		t.Errorf("NotBefore = %v, want 2026", c.NotBefore)
	}
	if c.NotAfter == nil || c.NotAfter.Year() != 2027 {
		t.Errorf("NotAfter = %v, want 2027", c.NotAfter)
	}
	if len(w.list()) != 0 {
		t.Errorf("unexpected warnings: %v", w.list())
	}
}

func TestParseCertificate_GoldenLegalPerson(t *testing.T) {
	var w warnings
	c := parseCertificate(fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТОВ ТЕСТ",
		"SUBJECT_SURNAME":      "ТЕСТОВ",
		"SUBJECT_GIVENNAME":    "ТЕСТОВИЧ",
		"SUBJECT_SERIALNUMBER": "IIN123456789011",
		"SUBJECT_ORGUNIT_NAME": "BIN123456789021",
		"SUBJECT_ORG_NAME":     `АО "ТЕСТ"`,
		"SUBJECT_COUNTRYNAME":  "KZ",
		"NOTBEFORE":            "08.05.2026 07:10:15 +00:00",
		"NOTAFTER":             "08.05.2027 07:10:15 +00:00",
		"KEY_USAGE":            "digitalSignature nonRepudiation keyAgreement ",
		"EXT_KEY_USAGE":        "E-mail Protection (1.3.6.1.5.5.7.3.4); 1.2.398.3.3.4.1.2 (1.2.398.3.3.4.1.2); 1.2.398.3.3.4.1.2.1 (1.2.398.3.3.4.1.2.1); ",
		"SIGNATURE_ALG":        "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)(1.2.398.3.10.1.1.2.3.2)",
		"CERT_SN":              "303EEBDF17969F3EDEDE9BD9828FB1355AABBE4E",
	}), nil, "", &w)

	if c.Subject.IIN != "123456789011" {
		t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
	}
	if c.Subject.BIN != "123456789021" {
		t.Errorf("BIN = %q, want 123456789021", c.Subject.BIN)
	}
	if c.Subject.Organization != `АО "ТЕСТ"` {
		t.Errorf("Organization = %q", c.Subject.Organization)
	}
	if c.OwnerType != "LEGAL_PERSON" {
		t.Errorf("OwnerType = %q, want LEGAL_PERSON", c.OwnerType)
	}
	if !contains(c.Roles, "ORGANIZATION") || !contains(c.Roles, "CEO") {
		t.Errorf("Roles = %v, want to contain ORGANIZATION and CEO", c.Roles)
	}
	if c.KeyAlgorithm != "gost2015-512" {
		t.Errorf("KeyAlgorithm = %q, want gost2015-512", c.KeyAlgorithm)
	}
	if c.SerialNumber != "303EEBDF17969F3EDEDE9BD9828FB1355AABBE4E" {
		t.Errorf("SerialNumber = %q", c.SerialNumber)
	}
	if len(w.list()) != 0 {
		t.Errorf("unexpected warnings: %v", w.list())
	}
}
