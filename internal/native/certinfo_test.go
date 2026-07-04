package native

import "testing"

func TestAfterEq(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// "name=value" renderings — the prefix is stripped.
		{"notBefore=08.05.2026 06:45:13 +00:00", "08.05.2026 06:45:13 +00:00"},
		{"certificateSerialNumber=6C425659BD2F", "6C425659BD2F"},
		{"serialNumber=IIN123456789011", "IIN123456789011"},
		{"C=KZ", "KZ"},
		{"CN=ТЕСТОВ ТЕСТ", "ТЕСТОВ ТЕСТ"},
		{"extendedKeyUsage=E-mail Protection (1.3.6.1.5.5.7.3.4)", "E-mail Protection (1.3.6.1.5.5.7.3.4)"},
		{"certificatePolicies=1.2.398.3.3.2", "1.2.398.3.3.2"},
		// DN aggregates render with spaces around '=', so nothing is stripped.
		{"CN = ТЕСТОВ ТЕСТ, C = KZ", "CN = ТЕСТОВ ТЕСТ, C = KZ"},
		// A base64 public key has non-identifier bytes before its '=' padding.
		{"MIGsMCMGCSqDDg\nAAEgYBn==", "MIGsMCMGCSqDDg\nAAEgYBn=="},
		// Degenerate inputs are returned unchanged.
		{"", ""},
		{"=leading", "=leading"},
		{"noequals", "noequals"},
	}
	for _, c := range cases {
		if got := afterEq(c.in); got != c.want {
			t.Errorf("afterEq(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
