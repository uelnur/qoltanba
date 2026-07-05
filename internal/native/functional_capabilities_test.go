//go:build qoltanba_functional

package native

import "testing"

func TestFunctional_Capabilities(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	caps := p.Capabilities()
	t.Logf("version=%s pool=%d signCMS=%v verifyCMS=%v signXML=%v verifyXML=%v certInfo=%v validate=%v tsa=%v zip=%v",
		caps.Version, caps.PoolSize, caps.SignCMS, caps.VerifyCMS, caps.SignXML, caps.VerifyXML,
		caps.CertInfo, caps.Validate, caps.Timestamp, caps.ZipSign)
	if !caps.SignCMS || !caps.VerifyCMS || !caps.CertInfo {
		t.Fatalf("expected the base SignCMS/VerifyCMS/CertInfo capabilities")
	}
}
