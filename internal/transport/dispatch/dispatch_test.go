package dispatch

import (
	"context"
	"errors"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func TestHandle_CertInfo(t *testing.T) {
	f := &fake.Provider{Props: fake.Fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN900130300123",
	})}
	svc := core.New(f)

	out, err := Handle(context.Background(), svc, "cert-info", []byte(`{"cert":"UEVN","encoding":"pem"}`))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	res, ok := out.(core.CertInfoOutput)
	if !ok {
		t.Fatalf("output type %T", out)
	}
	if res.Certificate.Subject.IIN != "900130300123" {
		t.Errorf("IIN = %q", res.Certificate.Subject.IIN)
	}
}

func TestHandle_UnknownOp(t *testing.T) {
	_, err := Handle(context.Background(), core.New(&fake.Provider{}), "nope", []byte(`{}`))
	var de *core.Error
	if !errors.As(err, &de) || de.Kind != core.KindInvalid {
		t.Fatalf("err = %v, want KindInvalid", err)
	}
}

func TestHandle_MalformedPayload(t *testing.T) {
	_, err := Handle(context.Background(), core.New(&fake.Provider{}), "verify", []byte(`{not json`))
	var de *core.Error
	if !errors.As(err, &de) || de.Kind != core.KindInvalid {
		t.Fatalf("err = %v, want KindInvalid", err)
	}
}

func TestHandle_ServiceFaultPropagates(t *testing.T) {
	f := &fake.Provider{VerifyErr: provider.ErrUnsupported}
	_, err := Handle(context.Background(), core.New(f), "verify", []byte(`{"format":"cms","signature":"eA=="}`))
	var de *core.Error
	if !errors.As(err, &de) || de.Kind != core.KindUnsupported {
		t.Fatalf("err = %v, want KindUnsupported", err)
	}
}

func TestValid(t *testing.T) {
	for _, op := range Ops {
		if !Valid(op) {
			t.Errorf("Valid(%q) = false", op)
		}
	}
	if Valid("bogus") {
		t.Error("Valid(bogus) = true")
	}
}

func TestHandle_CertInfoBatch(t *testing.T) {
	f := &fake.Provider{Props: fake.Fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN900130300123",
	})}
	svc := core.New(f)

	out, err := Handle(context.Background(), svc, "cert-info-batch",
		[]byte(`{"items":[{"cert":"UEVN","encoding":"pem"},{"cert":"UEVN","encoding":"pem"}]}`))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	res, ok := out.(core.BatchOutput[core.CertInfoOutput])
	if !ok {
		t.Fatalf("output type %T", out)
	}
	if res.Total != 2 || res.Succeeded != 2 {
		t.Fatalf("summary = %+v, want total=2 succeeded=2", res)
	}
}

func TestHandle_BatchMalformedItem(t *testing.T) {
	_, err := Handle(context.Background(), core.New(&fake.Provider{}), "sign-batch",
		[]byte(`{"items":[{"format":"bogus","data":"eA=="}]}`))
	var de *core.Error
	if !errors.As(err, &de) || de.Kind != core.KindInvalid {
		t.Fatalf("err = %v, want KindInvalid", err)
	}
}
