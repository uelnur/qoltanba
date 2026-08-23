package provider

import "testing"

func TestParseLocale(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Locale
	}{
		{"", LocaleEN},
		{"ru", LocaleRU},
		{"RU", LocaleRU},
		{"ru-KZ", LocaleRU},
		{"kk", LocaleKK},
		{"kk_KZ", LocaleKK},
		{"en-US", LocaleEN},
		{"fr", LocaleEN}, // unsupported falls back rather than failing
		{"fr-FR, ru;q=0.8", LocaleRU},
		{"ru;q=0.9,en;q=0.8", LocaleRU},
	} {
		if got := ParseLocale(tc.in); got != tc.want {
			t.Errorf("ParseLocale(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLocalizeKeepsContract pins what must not move between languages: the stable
// key and the raw code are the contract, only the prose is translated.
func TestLocalizeKeepsContract(t *testing.T) {
	err := NewNativeError("VerifyCMS", 0x08F0000B, "expired", ErrCertExpired)
	en := Explain(err)

	ru := Localize(en, LocaleRU)
	if ru.Key != en.Key || ru.Code != en.Code {
		t.Errorf("key/code changed with the language: %+v vs %+v", ru, en)
	}
	if ru.Message == en.Message || ru.Message == "" || ru.Action == "" {
		t.Errorf("russian rendering missing: %+v", ru)
	}

	kk := Localize(en, LocaleKK)
	if kk.Message == en.Message || kk.Message == ru.Message || kk.Message == "" {
		t.Errorf("kazakh rendering missing or duplicated: %+v", kk)
	}
}

func TestLocalizeFallsBackToEnglish(t *testing.T) {
	exp := Explanation{Key: "unknown.key", Message: "English text", Action: "Do this."}
	for _, loc := range []Locale{LocaleRU, LocaleKK, LocaleEN, Locale("fr")} {
		if got := Localize(exp, loc); got.Message != exp.Message || got.Action != exp.Action {
			t.Errorf("Localize(%q) = %+v, want the English text untouched", loc, got)
		}
	}
}

// TestTranslationsCoverCatalog keeps a new catalog entry from silently shipping
// untranslated: every key must exist in every locale table.
func TestTranslationsCoverCatalog(t *testing.T) {
	keys := make([]string, 0, len(catalog)+1)
	for _, e := range catalog {
		keys = append(keys, e.key)
	}
	keys = append(keys, genericEntry.key)

	for loc, table := range translations {
		for _, key := range keys {
			tr, ok := table[key]
			if !ok {
				t.Errorf("locale %q has no translation for %q", loc, key)
				continue
			}
			if tr.message == "" || tr.action == "" {
				t.Errorf("locale %q has an empty rendering for %q", loc, key)
			}
		}
	}
}
