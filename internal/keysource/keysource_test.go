package keysource

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
)

func TestResolveInline_WritesTempFileAndCleansUp(t *testing.T) {
	r := New(WithInline(true))
	h, err := r.Resolve(context.Background(), core.KeySpec{
		Inline: &core.InlineKey{P12: []byte("P12BYTES"), Password: "pw"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if h.Ref.Storage != provider.StoragePKCS12 || h.Ref.Path == "" {
		t.Fatalf("unexpected ref %+v", h.Ref)
	}
	if data, err := os.ReadFile(h.Ref.Path); err != nil || string(data) != "P12BYTES" {
		t.Fatalf("temp key content = %q, err %v", data, err)
	}
	if h.Ref.Password != "pw" {
		t.Errorf("password not passed through")
	}
	h.Release()
	if _, err := os.Stat(h.Ref.Path); !os.IsNotExist(err) {
		t.Errorf("temp key not removed after Release")
	}
}

func TestResolveInline_DisabledByDefault(t *testing.T) {
	r := New()
	_, err := r.Resolve(context.Background(), core.KeySpec{Inline: &core.InlineKey{P12: []byte("x")}})
	if !errors.Is(err, ErrInlineDisabled) {
		t.Fatalf("want ErrInlineDisabled, got %v", err)
	}
}

func TestResolvePathAndToken(t *testing.T) {
	r := New()
	h, err := r.Resolve(context.Background(), core.KeySpec{Path: &core.PathKey{Path: "/k.p12", Password: "pw"}})
	if err != nil || h.Ref.Path != "/k.p12" || h.Ref.Password != "pw" {
		t.Fatalf("path resolve: %+v err %v", h.Ref, err)
	}

	h, err = r.Resolve(context.Background(), core.KeySpec{Token: &core.TokenKey{Storage: "kaztoken", PIN: "1234"}})
	if err != nil || h.Ref.Storage != provider.StorageKaztoken || h.Ref.Password != "1234" {
		t.Fatalf("token resolve: %+v err %v", h.Ref, err)
	}

	if _, err := r.Resolve(context.Background(), core.KeySpec{Token: &core.TokenKey{Storage: "nope"}}); err == nil {
		t.Error("expected error for unknown token storage")
	}
}

func TestResolveKeyID_Unsupported(t *testing.T) {
	r := New()
	if _, err := r.Resolve(context.Background(), core.KeySpec{KeyID: "abc"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}
