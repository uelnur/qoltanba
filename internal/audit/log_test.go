package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubSigner signs deterministically so a test can tell a valid signature from a
// stale one without an RSA key.
type stubSigner struct{ fail bool }

func (s stubSigner) KeyID() string { return "kid" }

func (s stubSigner) Sign(claims any) (string, error) {
	if s.fail {
		return "", os.ErrPermission
	}
	seal, ok := claims.(Seal)
	if !ok {
		return "sig", nil
	}
	return "sig:" + seal.Hash, nil
}

// checkStubSignature is the verifier matching stubSigner.
func checkStubSignature(e Entry) error {
	if e.Signature != "sig:"+e.Hash {
		return os.ErrInvalid
	}
	return nil
}

func newLog(t *testing.T, signer Signer) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	now := time.Unix(1_700_000_000, 0).UTC()
	l, err := Open(Config{Path: path, Now: func() time.Time {
		now = now.Add(time.Second)
		return now
	}}, signer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func TestAppendChainsEntries(t *testing.T) {
	l, path := newLog(t, stubSigner{})

	first, err := l.Append(Event{Op: "verify", Subject: "doc-1", Outcome: "valid", Signer: "123456789011"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	second, err := l.Append(Event{Op: "sign", Subject: "doc-2", Outcome: "ok"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	if first.Seq != 1 || second.Seq != 2 {
		t.Errorf("sequence = %d, %d", first.Seq, second.Seq)
	}
	if first.PrevHash != genesisHash {
		t.Errorf("first entry prevHash = %q, want the genesis marker", first.PrevHash)
	}
	if second.PrevHash != first.Hash {
		t.Error("entries are not chained")
	}
	if second.Signature != "sig:"+second.Hash {
		t.Errorf("entry not signed: %q", second.Signature)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; lines != 2 {
		t.Errorf("journal holds %d lines, want 2", lines)
	}
	if res := Verify(bytes.NewReader(raw), checkStubSignature); !res.Intact || res.Entries != 2 {
		t.Errorf("verify = %+v", res)
	}
}

// TestVerifyDetectsAnEditedEntry is the property the whole design exists for.
func TestVerifyDetectsAnEditedEntry(t *testing.T) {
	l, path := newLog(t, stubSigner{})
	_, _ = l.Append(Event{Op: "verify", Subject: "doc-1", Outcome: "invalid"})
	_, _ = l.Append(Event{Op: "verify", Subject: "doc-2", Outcome: "valid"})
	_ = l.Close()

	raw, _ := os.ReadFile(path)
	edited := bytes.Replace(raw, []byte(`"outcome":"invalid"`), []byte(`"outcome":"valid"`), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("test did not modify the journal")
	}

	res := Verify(bytes.NewReader(edited), nil)
	if res.Intact || res.BrokenAt != 1 {
		t.Fatalf("verify = %+v, want a break at entry 1", res)
	}
	if !strings.Contains(res.Reason, "hash") {
		t.Errorf("reason = %q, want it to name the hash mismatch", res.Reason)
	}
}

// TestVerifyDetectsARemovedEntry covers the other way to rewrite history.
func TestVerifyDetectsARemovedEntry(t *testing.T) {
	l, path := newLog(t, stubSigner{})
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Event{Op: "verify", Outcome: "valid"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	_ = l.Close()

	raw, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	without := bytes.Join([][]byte{lines[0], lines[2]}, []byte("\n"))

	res := Verify(bytes.NewReader(without), nil)
	if res.Intact {
		t.Fatal("removing an entry went unnoticed")
	}
	if res.BrokenAt != 2 {
		t.Errorf("brokenAt = %d, want the missing entry's position", res.BrokenAt)
	}
}

// TestVerifyDetectsAResealedEntry shows what the signature adds: recomputing the
// hashes after an edit repairs the chain, but the signature no longer matches.
func TestVerifyDetectsAResealedEntry(t *testing.T) {
	l, path := newLog(t, stubSigner{})
	_, _ = l.Append(Event{Op: "verify", Subject: "doc-1", Outcome: "invalid"})
	_, _ = l.Append(Event{Op: "verify", Subject: "doc-2", Outcome: "valid"})
	_ = l.Close()

	raw, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	var first Entry
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Forge entry 1 and re-hash the chain, exactly as an attacker with write
	// access but no key would.
	first.Outcome = "valid"
	first.Hash = hashOf(first)
	forgedFirst, _ := json.Marshal(first)

	var second Entry
	_ = json.Unmarshal(lines[1], &second)
	second.PrevHash = first.Hash
	second.Hash = hashOf(second)
	forgedSecond, _ := json.Marshal(second)

	forged := bytes.Join([][]byte{forgedFirst, forgedSecond}, []byte("\n"))

	if res := Verify(bytes.NewReader(forged), nil); !res.Intact {
		t.Fatal("re-hashed chain should look intact without signature checking — that is why signatures exist")
	}
	res := Verify(bytes.NewReader(forged), checkStubSignature)
	if res.Intact || res.BrokenAt != 1 {
		t.Fatalf("verify with signatures = %+v, want a break at entry 1", res)
	}
}

// TestOpenResumesTheChain keeps a restart from forking history.
func TestOpenResumesTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, err := Open(Config{Path: path}, stubSigner{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first, _ := l1.Append(Event{Op: "verify", Outcome: "valid"})
	_ = l1.Close()

	l2, err := Open(Config{Path: path}, stubSigner{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	second, err := l2.Append(Event{Op: "verify", Outcome: "valid"})
	if err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	if second.Seq != 2 || second.PrevHash != first.Hash {
		t.Errorf("chain restarted instead of resuming: %+v", second)
	}

	raw, _ := os.ReadFile(path)
	if res := Verify(bytes.NewReader(raw), checkStubSignature); !res.Intact || res.Entries != 2 {
		t.Errorf("verify after restart = %+v", res)
	}
}

// TestAppendFailsWhenSigningFails keeps an unsigned entry out of the journal: a
// gap is honest, a silently unsigned entry is not.
func TestAppendFailsWhenSigningFails(t *testing.T) {
	l, path := newLog(t, stubSigner{fail: true})
	if _, err := l.Append(Event{Op: "verify", Outcome: "valid"}); err == nil {
		t.Fatal("append should fail when the entry cannot be signed")
	}
	_ = l.Close()

	raw, _ := os.ReadFile(path)
	if len(bytes.TrimSpace(raw)) != 0 {
		t.Errorf("journal holds %q after a failed signing", raw)
	}
}

func TestOpenRefusesAnUnreadableJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("not json\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Appending to a journal whose end cannot be read would fork the chain
	// silently, so this must fail loudly instead.
	if _, err := Open(Config{Path: path}, stubSigner{}); err == nil {
		t.Fatal("Open should refuse a journal it cannot read to the end")
	}
}
