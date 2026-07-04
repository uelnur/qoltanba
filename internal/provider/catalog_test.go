package provider

import "testing"

func TestExplain_NilIsZero(t *testing.T) {
	if got := Explain(nil); got != (Explanation{}) {
		t.Errorf("Explain(nil) = %+v, want zero", got)
	}
}

func TestExplain_SentinelMatch(t *testing.T) {
	exp := Explain(ErrCertExpired)
	if exp.Key != "cert.expired" {
		t.Errorf("Key = %q, want cert.expired", exp.Key)
	}
	if exp.Message == "" || exp.Action == "" {
		t.Errorf("Message/Action must be set: %+v", exp)
	}
	if exp.Code != "" {
		t.Errorf("Code = %q, want empty for a bare sentinel", exp.Code)
	}
}

func TestExplain_NativeErrorCarriesCodeAndSentinel(t *testing.T) {
	err := NewNativeError("VerifyCMS", 0x08F0000B, "expired", ErrCertExpired)
	exp := Explain(err)
	if exp.Code != "0x08F0000B" {
		t.Errorf("Code = %q, want 0x08F0000B", exp.Code)
	}
	if exp.Key != "cert.expired" {
		t.Errorf("Key = %q, want cert.expired", exp.Key)
	}
}

func TestExplain_UnrecognizedCodeFallsBackButKeepsCode(t *testing.T) {
	// A NativeError with a code but no recognized sentinel.
	err := NewNativeError("SignCMS", 0x08F00099, "weird", nil)
	exp := Explain(err)
	if exp.Code != "0x08F00099" {
		t.Errorf("Code = %q, want 0x08F00099", exp.Code)
	}
	if exp.Key != genericEntry.key {
		t.Errorf("Key = %q, want fallback %q", exp.Key, genericEntry.key)
	}
	if exp.Message == "" {
		t.Error("fallback Message must be set")
	}
}

// Every catalog entry must be complete — a missing message or action would ship a
// blank remedy to callers.
func TestCatalog_EntriesComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range catalog {
		if e.sentinel == nil {
			t.Errorf("entry %q has a nil sentinel", e.key)
		}
		if e.key == "" || e.message == "" || e.action == "" {
			t.Errorf("incomplete entry: %+v", e)
		}
		if seen[e.key] {
			t.Errorf("duplicate key %q", e.key)
		}
		seen[e.key] = true
	}
}
