package core

import (
	"context"
	"errors"
	"testing"
)

// recordingResolver returns a fixed path and records that it ran and was released.
type recordingResolver struct {
	path     string
	err      error
	calls    int
	released bool
}

func (r *recordingResolver) Resolve(_ context.Context, _ DataRef) (ResolvedData, error) {
	r.calls++
	if r.err != nil {
		return ResolvedData{}, r.err
	}
	return NewResolvedData(r.path, func() { r.released = true }), nil
}

func TestSign_DataRefPassesPathToDriver(t *testing.T) {
	f := &fakeProvider{}
	res := &recordingResolver{path: "/spool/data.bin"}
	svc := New(f, WithKeySource(staticKeySource{}), WithDataResolver(res))

	_, err := svc.Sign(context.Background(), SignInput{
		Key:     KeySpec{KeyID: "k"},
		Format:  FormatCMS,
		DataRef: DataRef{URL: "https://example/data"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", res.calls)
	}
	if !res.released {
		t.Error("resolved data was not released")
	}
	if f.lastSignCMS == nil {
		t.Fatal("driver SignCMS was not called")
	}
	if f.lastSignCMS.Path != "/spool/data.bin" {
		t.Fatalf("driver Path = %q, want /spool/data.bin", f.lastSignCMS.Path)
	}
}

func TestVerify_DataRefPassesPathToDriver(t *testing.T) {
	f := &fakeProvider{}
	res := &recordingResolver{path: "/spool/orig.bin"}
	svc := New(f, WithDataResolver(res))

	_, err := svc.Verify(context.Background(), VerifyInput{
		Format:    FormatCMS,
		Signature: []byte("sig"),
		Detached:  true,
		DataRef:   DataRef{Path: "/data/orig.bin"},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if f.lastVerify == nil || f.lastVerify.Path != "/spool/orig.bin" {
		t.Fatalf("driver Path = %q, want /spool/orig.bin", f.lastVerify.Path)
	}
	if !res.released {
		t.Error("resolved data was not released")
	}
}

func TestSign_DataRefWithoutResolverIsUnavailable(t *testing.T) {
	svc := New(&fakeProvider{}, WithKeySource(staticKeySource{}))
	_, err := svc.Sign(context.Background(), SignInput{Format: FormatCMS, Key: KeySpec{KeyID: "k"}, DataRef: DataRef{URL: "https://x/y"}})
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindUnavailable {
		t.Fatalf("err = %v, want KindUnavailable", err)
	}
}

func TestSign_DataRefNonCMSRejected(t *testing.T) {
	svc := New(&fakeProvider{}, WithKeySource(staticKeySource{}), WithDataResolver(&recordingResolver{path: "/x"}))
	_, err := svc.Sign(context.Background(), SignInput{Format: FormatXML, Key: KeySpec{KeyID: "k"}, DataRef: DataRef{Path: "/data"}})
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindInvalid {
		t.Fatalf("err = %v, want KindInvalid", err)
	}
}

func TestSign_ResolverErrorPropagatesKind(t *testing.T) {
	res := &recordingResolver{err: &Error{Kind: KindInvalid, Op: "dataref", err: errors.New("scheme not allowed")}}
	svc := New(&fakeProvider{}, WithKeySource(staticKeySource{}), WithDataResolver(res))
	_, err := svc.Sign(context.Background(), SignInput{Format: FormatCMS, Key: KeySpec{KeyID: "k"}, DataRef: DataRef{URL: "ftp://x/y"}})
	var de *Error
	if !errors.As(err, &de) || de.Kind != KindInvalid {
		t.Fatalf("err = %v, want KindInvalid (preserved from resolver)", err)
	}
}
