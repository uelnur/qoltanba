package pki

import "testing"

func TestKeyUserForOID(t *testing.T) {
	cases := map[string]KeyUser{
		"1.2.398.3.3.4.1.1":      KeyUserIndividual,
		"1.2.398.3.3.4.1.2.1":    KeyUserCEO,
		"1.2.398.3.3.4.1.2.2":    KeyUserCanSign,
		"1.2.398.3.3.4.1.2.5":    KeyUserEmployee,
		"1.2.398.3.3.4.1.2.6":    KeyUserInfosystem,
		"1.2.398.3.3.4.1.2.6.71": KeyUserInfosystem, // конкретная ИС (префикс)
		"1.2.398.5.19.1.2.2.1":   KeyUserTreasuryClient,
		"1.2.398.3.3.4.2.1":      KeyUserNCAAdmin,
		"1.2.398.3.3.4.3.2.1":    KeyUserIdentDigitalID,
		"1.3.6.1.5.5.7.3.4":      KeyUser(""), // E-mail Protection — не роль
	}
	for oid, want := range cases {
		if got := KeyUserForOID(oid); got != want {
			t.Errorf("KeyUserForOID(%s) = %q, want %q", oid, got, want)
		}
	}
}

func TestKeyUsersFromEKU(t *testing.T) {
	eku := []string{"1.3.6.1.5.5.7.3.4", "1.2.398.3.3.4.1.2", "1.2.398.3.3.4.1.2.1"}
	got := KeyUsersFromEKU(eku)
	want := []KeyUser{KeyUserOrganization, KeyUserCEO}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNameFromRegistry(t *testing.T) {
	if n := Name("1.2.398.3.3.4.1.2.1"); n == "" {
		t.Error("официальное имя не загрузилось из oids-nuc.json")
	}
}

func TestTSAAndAlgs(t *testing.T) {
	if TSAPolicyID(DefaultTSAPolicy) != "1.2.398.3.3.2.6.4" {
		t.Error("дефолтная TSA-политика неверна")
	}
	if DigestOIDForSignOID(SignSHA256RSA) != DigestSHA256 {
		t.Error("digest для sha256WithRSA неверен")
	}
	if s, _ := XMLSignURIs(SignGOST2015_512); s != pkigovkzURNPfx+"gostr34102015-gostr34112015-512" {
		t.Errorf("XML URI ГОСТ-2015-512 неверен: %s", s)
	}
}

func TestOwnerType(t *testing.T) {
	if OwnerTypeFrom(false, true) != OwnerIndividual {
		t.Error("физлицо")
	}
	if OwnerTypeFrom(true, true) != OwnerLegalPerson {
		t.Error("сотрудник ЮЛ")
	}
	if OwnerTypeFrom(true, false) != OwnerInfosystem {
		t.Error("инфосистема")
	}
}

func TestCARegistry(t *testing.T) {
	if len(CACertificates()) < 20 {
		t.Errorf("ожидали >=20 CA, получили %d", len(CACertificates()))
	}
	if len(RootCRLs()) == 0 {
		t.Error("нет корневых CRL")
	}
	prod := CACertificatesFor(false)
	if len(prod) == 0 || len(prod) >= len(CACertificates()) {
		t.Error("фильтр prod/test не работает")
	}
}
