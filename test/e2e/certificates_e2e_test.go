//go:build qoltanba_functional

package e2e

import (
	"context"
	"slices"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
)

func TestFunctionalE2E_CertInfoFromKey(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: key})
	if err != nil {
		t.Fatalf("cert info: %v", err)
	}
	c := out.Certificate
	if c.SerialNumber == "" {
		t.Error("expected a certificate serial number")
	}
	if c.NotBefore == nil || c.NotAfter == nil {
		t.Error("expected validity dates")
	}
	if c.OwnerType == "" {
		t.Error("expected a derived owner type")
	}
	t.Logf("cert: serial=%s ownerType=%s keyAlg=%s roles=%v warnings=%d",
		c.SerialNumber, c.OwnerType, c.KeyAlgorithm, c.Roles, len(out.Warnings))
}

// TestFunctionalE2E_CertFieldsGolden pins the parsed certificate fields for the
// two consumer test keys against the live library — the fast counterpart is
// internal/core TestParseCertificate_Golden*, which parses the same values with
// no native library. Together they catch drift in the X509CertificateGetInfo
// rendering (e.g. a dropped "name=" prefix) and in the RK derivation.
func TestFunctionalE2E_CertFieldsGolden(t *testing.T) {
	svc, closer := newService(t)
	defer closer()

	t.Run("individual", func(t *testing.T) {
		out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
		if err != nil {
			t.Fatalf("cert info: %v", err)
		}
		c := out.Certificate
		if c.Subject.CommonName != "ТЕСТОВ ТЕСТ" {
			t.Errorf("CommonName = %q, want ТЕСТОВ ТЕСТ", c.Subject.CommonName)
		}
		if c.Subject.IIN != "123456789011" {
			t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
		}
		if c.Subject.BIN != "" {
			t.Errorf("BIN = %q, want empty for an individual", c.Subject.BIN)
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
		if c.SerialNumber != "6C425659BD2FC6DC587B871AEDE1857727CF8451" {
			t.Errorf("SerialNumber = %q", c.SerialNumber)
		}
		if c.NotBefore == nil || c.NotBefore.Year() != 2026 || c.NotAfter == nil || c.NotAfter.Year() != 2027 {
			t.Errorf("validity = [%v, %v], want 2026..2027", c.NotBefore, c.NotAfter)
		}
		if len(out.Warnings) != 0 {
			t.Errorf("unexpected warnings: %v", out.Warnings)
		}
	})

	t.Run("legalPerson", func(t *testing.T) {
		out, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey2(t)})
		if err != nil {
			t.Fatalf("cert info: %v", err)
		}
		c := out.Certificate
		if c.Subject.IIN != "123456789011" {
			t.Errorf("IIN = %q, want 123456789011", c.Subject.IIN)
		}
		if c.Subject.BIN != "123456789021" {
			t.Errorf("BIN = %q, want 123456789021", c.Subject.BIN)
		}
		if c.Subject.Organization != `АО "ТЕСТ"` {
			t.Errorf("Organization = %q, want АО \"ТЕСТ\"", c.Subject.Organization)
		}
		if c.OwnerType != "LEGAL_PERSON" {
			t.Errorf("OwnerType = %q, want LEGAL_PERSON", c.OwnerType)
		}
		if !slices.Contains(c.Roles, "ORGANIZATION") || !slices.Contains(c.Roles, "CEO") {
			t.Errorf("Roles = %v, want to contain ORGANIZATION and CEO", c.Roles)
		}
		if c.SerialNumber != "303EEBDF17969F3EDEDE9BD9828FB1355AABBE4E" {
			t.Errorf("SerialNumber = %q", c.SerialNumber)
		}
	})
}
