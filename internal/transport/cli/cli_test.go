package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func TestRun_CertInfo(t *testing.T) {
	f := &fake.Provider{Props: fake.Fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN900130300123",
	})}
	svc := core.New(f)

	in := strings.NewReader(`{"cert":"UEVN","encoding":"pem"}`) // "PEM" in base64
	var out bytes.Buffer
	code := Run(context.Background(), svc, "cert-info", in, &out)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; out=%s", code, out.String())
	}
	var res core.CertInfoOutput
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Certificate.Subject.IIN != "900130300123" {
		t.Errorf("IIN = %q", res.Certificate.Subject.IIN)
	}
}

func TestRun_HardErrorExitCode(t *testing.T) {
	f := &fake.Provider{VerifyErr: provider.ErrUnsupported}
	svc := core.New(f)
	var out bytes.Buffer
	code := Run(context.Background(), svc, "verify", strings.NewReader(`{"format":"cms","signature":"eA=="}`), &out)
	if code != 3 { // KindUnsupported
		t.Fatalf("exit = %d, want 3; out=%s", code, out.String())
	}
}

func TestRun_UnknownOp(t *testing.T) {
	var out bytes.Buffer
	code := Run(context.Background(), core.New(&fake.Provider{}), "nope", strings.NewReader(`{}`), &out)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
