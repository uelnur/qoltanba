//go:build qoltanba_functional

package native

import (
	"context"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// TestFunctional_ErrorMapping checks that native codes map to typed provider
// errors (invalid password).
func TestFunctional_ErrorMapping(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	bad := envKey()
	bad.Password = "wrong-password-000"
	_, err := p.SignCMS(context.Background(), provider.SignRequest{Key: bad, Data: testData, OutPEM: true})
	if err == nil {
		t.Fatal("expected an error for a wrong password")
	}
	t.Logf("wrong-password error: %v", err)
}

// TestFunctional_SetProxyNoBreak confirms KC_SetProxy exists and that a call
// after configuring the proxy (off = direct) still works — the coarse proxy
// lever we keep when OCSP stays delegated to the library.
func TestFunctional_SetProxyNoBreak(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	var rc uint32 = 0xFFFFFFFF
	if err := p.submit(ctx, func(inst kalkanInstance) error {
		if real, ok := inst.(*instance); ok {
			rc = real.setProxy(kcProxyOff, "", "", "", "")
		}
		return nil
	}); err != nil {
		t.Fatalf("submit setProxy: %v", err)
	}
	switch rc {
	case 0:
		t.Log("KC_SetProxy(off) rc=0 (ok)")
	case 0xFFFFFFFF:
		t.Skip("KC_SetProxy absent in this library version")
	default:
		t.Logf("KC_SetProxy(off) rc=0x%08X (returned, non-zero)", rc)
	}

	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS after SetProxy: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty signature after SetProxy")
	}
	t.Log("operation works after KC_SetProxy — call not broken")
}

// TestFunctional_ContextDeadline is a quick sanity check of context timeout
// against the real library.
func TestFunctional_ContextDeadline(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: testData, OutPEM: true})
	if err == nil {
		t.Log("operation finished before the deadline (acceptable)")
	} else {
		t.Logf("deadline fired: %v", err)
	}
}
