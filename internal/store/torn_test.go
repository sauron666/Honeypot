package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/event"
)

func mkEv(m string) *event.Event {
	return event.New(event.ClassDecoyInteraction, 1, event.SeverityLow, event.PlaneHoneyd).WithMessage("%s", m)
}

// A crash mid-append leaves a partial final line. The director must recover and
// restart -- refusing to start on its own evidence is the worst possible
// failure for a product started and killed via scheduled tasks.
func TestReopenAfterTornFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	ctx := context.Background()

	s1, _ := OpenFile(path, DefaultFileOptions())
	for i := 0; i < 4; i++ {
		if err := s1.Append(ctx, mkEv("a")); err != nil {
			t.Fatal(err)
		}
	}
	seq1, hash1 := s1.Head()
	s1.Close()

	// Torn write: a partial JSON record with no terminating newline.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"time":123,"class_uid":9001,"metadata":{"uid":"01ABC`)
	f.Close()

	s2, err := OpenFile(path, DefaultFileOptions())
	if err != nil {
		t.Fatalf("director refused to start after a crash-torn final line: %v", err)
	}
	if s2.RecoveredBytes() == 0 {
		t.Fatal("the torn tail was not reported as recovered")
	}
	// Resume must continue the exact chain the durable records ended on.
	seq2, hash2 := s2.Head()
	if seq2 != seq1 || hash2 != hash1 {
		t.Fatalf("resume lost the head after recovery: %d/%s vs %d/%s",
			seq1, hash1[:12], seq2, hash2[:12])
	}
	if err := s2.Append(ctx, mkEv("b")); err != nil {
		t.Fatalf("append after recovery failed: %v", err)
	}
	if err := s2.Verify(ctx); err != nil {
		t.Fatalf("chain broke after recovering from a torn line: %v", err)
	}
	s2.Close()

	// A cold reopen must now find an intact file with no torn tail.
	s3, err := OpenFile(path, DefaultFileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s3.RecoveredBytes() != 0 {
		t.Fatal("the torn tail was not physically removed; it came back on reopen")
	}
	if err := s3.Verify(ctx); err != nil {
		t.Fatalf("cold verify failed after recovery: %v", err)
	}
	s3.Close()
}

// Corruption in the MIDDLE of the file (a complete, newline-terminated record
// that does not decode) is tampering or disk rot, not a torn tail. It must
// still fail loudly -- silently repairing it would defeat tamper-evidence.
func TestMidFileCorruptionStillFailsLoudly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	ctx := context.Background()
	s1, _ := OpenFile(path, DefaultFileOptions())
	for i := 0; i < 4; i++ {
		s1.Append(ctx, mkEv("a"))
	}
	s1.Close()

	// Corrupt a complete line in the middle by rewriting the file with a
	// garbage record (newline-terminated) followed by a good one.
	data, _ := os.ReadFile(path)
	lines := strings.SplitN(string(data), "\n", 3)
	corrupt := lines[0] + "\n" + `{"broken":` + "\n" + strings.Join(lines[1:], "\n")
	os.WriteFile(path, []byte(corrupt), 0o600)

	if _, err := OpenFile(path, DefaultFileOptions()); err == nil {
		t.Fatal("mid-file corruption was silently accepted; tamper-evidence is broken")
	}
}

// A clean restart must resume the chain exactly, with no recovery needed.
func TestChainVerifiesAcrossCleanRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	ctx := context.Background()
	s1, _ := OpenFile(path, DefaultFileOptions())
	for i := 0; i < 5; i++ {
		s1.Append(ctx, mkEv("run1"))
	}
	seq1, hash1 := s1.Head()
	s1.Close()

	s2, err := OpenFile(path, DefaultFileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s2.RecoveredBytes() != 0 {
		t.Fatal("a clean restart reported a recovery it should not have")
	}
	seq2, hash2 := s2.Head()
	if seq2 != seq1 || hash2 != hash1 {
		t.Fatalf("clean resume lost the head: %d/%s vs %d/%s", seq1, hash1[:12], seq2, hash2[:12])
	}
	for i := 0; i < 5; i++ {
		s2.Append(ctx, mkEv("run2"))
	}
	if err := s2.Verify(ctx); err != nil {
		t.Fatalf("chain broke after a clean restart: %v", err)
	}
	s2.Close()
}
