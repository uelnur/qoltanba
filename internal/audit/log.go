// Package audit keeps a tamper-evident record of what the service did: who
// signed or verified what, when, and with what outcome.
//
// A plain log answers "what happened" only to someone who trusts the log. This
// one is built so the answer survives distrust: every entry carries the hash of
// the one before it, and every entry is signed with the service key. Rewriting
// history therefore means re-signing every entry after the change — which the
// service key would have to be stolen to do, and which an exported copy of the
// chain would still contradict.
//
// It is an operational record, not a substitute for the signatures themselves:
// it attests that this service performed a check, exactly as a verification
// receipt does, and the two share the same signer.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Signer signs one entry. It is the same RS256 service key that issues receipts
// and OIDC tokens, so a consumer verifies the chain against the published JWKS.
type Signer interface {
	Sign(claims any) (string, error)
	KeyID() string
}

// Entry is one recorded operation. The fields before Hash are what gets hashed
// and signed; Hash and Signature are the seal over them.
type Entry struct {
	Seq       uint64    `json:"seq"`
	At        time.Time `json:"at"`
	Op        string    `json:"op"`                // sign | verify | validate | …
	Actor     string    `json:"actor,omitempty"`   // who asked, when the caller says
	Subject   string    `json:"subject,omitempty"` // what was operated on (a digest, a document id)
	Signer    string    `json:"signer,omitempty"`  // whose signature was involved (IIN/BIN)
	Outcome   string    `json:"outcome"`           // valid | invalid | error | ok
	Detail    string    `json:"detail,omitempty"`
	PrevHash  string    `json:"prevHash"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature,omitempty"` // compact JWS over the entry
}

// Event is what a caller records; the log fills in the sequencing and the seal.
type Event struct {
	Op      string
	Actor   string
	Subject string
	Signer  string
	Outcome string
	Detail  string
}

// genesisHash starts the chain. A fixed, non-empty value makes "no previous
// entry" explicit rather than indistinguishable from an empty field.
const genesisHash = "genesis"

// Log is an append-only, hash-chained record.
type Log struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	signer   Signer
	now      func() time.Time
	seq      uint64
	prevHash string
	// sync forces the entry to disk before Append returns. Off by default: an
	// audit record is worth a flush, but paying an fsync per operation is a
	// deployment decision, not ours to make silently.
	sync bool
}

// Config parameterizes a Log.
type Config struct {
	// Path is the journal file. It is opened append-only and created 0600.
	Path string
	// Sync flushes each entry to disk before returning.
	Sync bool
	Now  func() time.Time
}

// Open opens (or creates) the journal and resumes its chain: the sequence and the
// previous hash are read from the last entry, so a restart continues the chain
// instead of starting a second one.
func Open(cfg Config, signer Signer) (*Log, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	seq, prev, err := tail(cfg.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	return &Log{
		file: f, writer: bufio.NewWriter(f), signer: signer,
		now: cfg.Now, seq: seq, prevHash: prev, sync: cfg.Sync,
	}, nil
}

// Append records an event and returns the sealed entry.
func (l *Log) Append(ev Event) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Seq: l.seq + 1, At: l.now().UTC(), Op: ev.Op, Actor: ev.Actor,
		Subject: ev.Subject, Signer: ev.Signer, Outcome: ev.Outcome, Detail: ev.Detail,
		PrevHash: l.prevHash,
	}
	e.Hash = hashOf(e)
	if l.signer != nil {
		sig, err := l.signer.Sign(Seal{Seq: e.Seq, Hash: e.Hash})
		if err != nil {
			return Entry{}, fmt.Errorf("audit: sign entry: %w", err)
		}
		e.Signature = sig
	}

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := l.writer.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.writer.Flush(); err != nil {
		return Entry{}, err
	}
	if l.sync {
		if err := l.file.Sync(); err != nil {
			return Entry{}, err
		}
	}
	// The in-memory chain head advances only after the entry is durable, so a
	// failed write cannot leave the next entry chained to something unwritten.
	l.seq, l.prevHash = e.Seq, e.Hash
	return e, nil
}

// Close flushes and closes the journal.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.writer.Flush(); err != nil {
		_ = l.file.Close()
		return err
	}
	return l.file.Close()
}

// Head reports the current sequence number and chain hash.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.prevHash
}

// hashOf computes an entry's chain hash over its content plus the previous hash.
// The fields are hashed in a fixed textual form rather than as JSON, so a change
// in field order or encoding cannot silently change the hash of the same facts.
func hashOf(e Entry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		e.Seq, e.At.UTC().Format(time.RFC3339Nano), e.Op, e.Actor,
		e.Subject, e.Signer, e.Outcome, e.Detail, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// Seal is what actually gets signed: the entry's sequence number and its chain
// hash. Signing the hash rather than the whole entry keeps verification
// unambiguous — the entry as written also carries the signature field, so
// re-serializing it to check a signature over itself is circular.
type Seal struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// VerifyResult reports the outcome of checking a journal.
type VerifyResult struct {
	Entries uint64 `json:"entries"`
	// BrokenAt is the sequence number where the chain first failed, 0 when intact.
	BrokenAt uint64 `json:"brokenAt,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Head     string `json:"head,omitempty"`
	Intact   bool   `json:"intact"`
}

// Verify walks a journal and checks that every entry hashes to what it claims and
// links to its predecessor. It reports the first break rather than a boolean: an
// auditor needs to know where history was altered, not merely that it was.
//
// A verifier is optional; when given, each entry's signature is checked too,
// which is what makes the chain resistant to a wholesale rewrite (recomputing
// hashes is easy, re-signing them is not).
func Verify(r io.Reader, verifySignature func(entry Entry) error) VerifyResult {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	res := VerifyResult{Intact: true}
	prev := genesisHash
	var expectedSeq uint64 = 1

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return broken(res, expectedSeq, "entry is not valid JSON: "+err.Error())
		}
		switch {
		case e.Seq != expectedSeq:
			return broken(res, expectedSeq, fmt.Sprintf("sequence jumped to %d (an entry was removed or reordered)", e.Seq))
		case e.PrevHash != prev:
			return broken(res, e.Seq, "previous hash does not match the entry before it")
		case e.Hash != hashOf(e):
			return broken(res, e.Seq, "entry content does not match its hash (it was edited)")
		}
		if verifySignature != nil {
			if err := verifySignature(e); err != nil {
				return broken(res, e.Seq, "signature check failed: "+err.Error())
			}
		}
		prev = e.Hash
		res.Entries++
		expectedSeq++
	}
	if err := scanner.Err(); err != nil {
		return broken(res, expectedSeq, "read: "+err.Error())
	}
	res.Head = prev
	return res
}

func broken(res VerifyResult, at uint64, reason string) VerifyResult {
	res.Intact, res.BrokenAt, res.Reason = false, at, reason
	return res
}

// tail reads the last entry of an existing journal to resume its chain. A missing
// file starts a new chain; an unreadable one is an error, because appending to a
// journal whose end is unknown would silently fork the chain.
func tail(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, genesisHash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("audit: read %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var last Entry
	found := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return 0, "", fmt.Errorf("audit: %s holds an unreadable entry: %w", path, err)
		}
		last, found = e, true
	}
	if err := scanner.Err(); err != nil {
		return 0, "", fmt.Errorf("audit: read %s: %w", path, err)
	}
	if !found {
		return 0, genesisHash, nil
	}
	return last.Seq, last.Hash, nil
}
