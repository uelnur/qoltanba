package native

import (
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// A by-reference request (Path set) must add KC_IN_FILE so the library reads the
// content from the path; an inline request must not.
func TestSignCMSFlags_InFile(t *testing.T) {
	if f := signCMSFlags(provider.SignRequest{}); f&kcInFile != 0 {
		t.Errorf("inline sign set KC_IN_FILE (flags=0x%X)", f)
	}
	if f := signCMSFlags(provider.SignRequest{Path: "/data.bin"}); f&kcInFile == 0 {
		t.Errorf("by-reference sign missing KC_IN_FILE (flags=0x%X)", f)
	}
}

func TestVerifyCMSFlags_InFile(t *testing.T) {
	if f := verifyCMSFlags(provider.VerifyRequest{}); f&kcInFile != 0 {
		t.Errorf("inline verify set KC_IN_FILE (flags=0x%X)", f)
	}
	if f := verifyCMSFlags(provider.VerifyRequest{Path: "/orig.bin"}); f&kcInFile == 0 {
		t.Errorf("by-reference verify missing KC_IN_FILE (flags=0x%X)", f)
	}
}
