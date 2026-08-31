package fusetrap

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/ransomware"
)

// clock is a controllable time source so tests measure detection latency in
// operations and simulated wall-clock without sleeping.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) tick(d time.Duration) time.Time {
	c.t = c.t.Add(d)
	return c.t
}

func newTestTrap(t *testing.T, onConfirm func(ransomware.Verdict, Metrics)) (*Trap, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	tr := New(Options{
		ShareID:     "test-share",
		Now:         c.now,
		OnConfirmed: onConfirm,
	})
	return tr, c
}

// encryptLike overwrites a file with high-entropy bytes and renames it with a
// ransomware extension — exactly what a cryptor does.
func encryptLike(tr *Trap, c *clock, path string) {
	buf := make([]byte, 2048)
	rand.Read(buf)
	c.tick(50 * time.Millisecond)
	tr.Read(path)
	c.tick(50 * time.Millisecond)
	tr.Write(path, buf)
	c.tick(10 * time.Millisecond)
	tr.Rename(path, path+".locked")
}

// walkFiles returns every file path in the trap, depth-first — the target list
// a cryptor builds when it enumerates the share.
func walkFiles(tr *Trap, dir string) []string {
	var out []string
	for _, e := range tr.List(dir) {
		p := dir + "/" + e.Name
		if dir == "/" {
			p = "/" + e.Name
		}
		if e.Dir {
			out = append(out, walkFiles(tr, p)...)
		} else {
			out = append(out, p)
		}
	}
	return out
}

func TestTrapSeedsARealisticShare(t *testing.T) {
	tr, _ := newTestTrap(t, nil)
	if !tr.IsDir("/Finance") || !tr.IsDir("/Backups/db") {
		t.Fatal("expected seeded directories")
	}
	if !tr.Exists("/Finance/_ACCOUNT_PASSWORDS.xlsx") {
		t.Fatal("expected the canary bait file")
	}
	// Seeded documents must start as low-entropy text, not noise, or the very
	// first write would look like encryption before any attack.
	body, ok := tr.Content("/Finance/2025/Q3-forecast.xlsx")
	if !ok || len(body) < 500 {
		t.Fatalf("seeded doc missing or too small: ok=%v len=%d", ok, len(body))
	}
	if e := ransomware.Entropy(body); e > 6.0 {
		t.Fatalf("seeded doc should be low-entropy text, got %.2f bits/byte", e)
	}
}

func TestBrowsingTheShareIsInstant(t *testing.T) {
	tr, c := newTestTrap(t, nil)
	// A legitimate user opens a few files. No signal, no tarpit.
	for _, p := range []string{"/Finance/2025/Q3-forecast.xlsx", "/HR/org-chart.pdf"} {
		c.tick(2 * time.Second)
		if d := tr.Read(p); d != 0 {
			t.Fatalf("reading %s imposed a tarpit of %v on a normal user", p, d)
		}
	}
	if tr.Verdict().Confirmed {
		t.Fatal("normal browsing must not confirm ransomware")
	}
}

func TestCanaryTouchIsAnImmediateSignal(t *testing.T) {
	tr, _ := newTestTrap(t, nil)
	// The first touch of a canary is a finding on its own.
	tr.Read("/Backups/RESTORE_KEYS.txt")
	if tr.Verdict().Score == 0 {
		t.Fatal("touching a canary should raise the score")
	}
	if tr.Metrics().CanaryHits != 1 {
		t.Fatalf("expected 1 canary hit, got %d", tr.Metrics().CanaryHits)
	}
}

func TestRansomwareIsConfirmedAndSnapshotFires(t *testing.T) {
	var confirmed *ransomware.Verdict
	var confirmMetrics Metrics
	tr, c := newTestTrap(t, func(v ransomware.Verdict, m Metrics) {
		vv := v
		confirmed = &vv
		confirmMetrics = m
	})

	// A cryptor walks the share encrypting everything it finds.
	targets := []string{
		"/Finance/2025/Q3-forecast.xlsx",
		"/Finance/2025/payroll-run.csv",
		"/Finance/wire-transfer-instructions.docx",
		"/Finance/_ACCOUNT_PASSWORDS.xlsx", // canary
		"/HR/salaries-2025.xlsx",
		"/HR/org-chart.pdf",
		"/Backups/db/dump-2025-08-30.sql",
		"/Backups/veeam-config.xml",
		"/Backups/RESTORE_KEYS.txt", // canary
	}
	for _, p := range targets {
		encryptLike(tr, c, p)
		if confirmed != nil {
			break
		}
	}

	if confirmed == nil {
		t.Fatal("ransomware was never confirmed; the snapshot callback never fired")
	}
	if !confirmed.Confirmed {
		t.Fatal("confirmation callback fired with an unconfirmed verdict")
	}
	// The whole point: we were sure well before the cryptor finished the share.
	if confirmMetrics.ConfirmOps == 0 {
		t.Fatal("expected a recorded op count at confirmation")
	}
	t.Logf("confirmed after %d ops, %d files touched, score %d",
		confirmMetrics.ConfirmOps, confirmMetrics.FilesTouched, confirmMetrics.Score)
}

func TestConfirmationFiresExactlyOnce(t *testing.T) {
	var calls int
	tr, c := newTestTrap(t, func(ransomware.Verdict, Metrics) { calls++ })
	// Sweep the whole share, then keep encrypting to be sure the callback does
	// not fire again after the first confirmation.
	targets := walkFiles(tr, "/")
	for round := 0; round < 3; round++ {
		for _, p := range targets {
			encryptLike(tr, c, p)
		}
	}
	if calls != 1 {
		t.Fatalf("snapshot/confirm callback fired %d times, want exactly 1", calls)
	}
}

func TestTarpitGrowsWithSuspicion(t *testing.T) {
	tr, c := newTestTrap(t, nil)
	// First write: barely suspicious, so the tarpit is small (a normal user who
	// saves one file must not be punished).
	first := tr.Write("/Finance/2025/Q3-forecast.xlsx", highEntropy())
	// Sweep the rest of the share like a cryptor.
	var last time.Duration
	for _, p := range walkFiles(tr, "/") {
		c.tick(20 * time.Millisecond)
		last = tr.Write(p, highEntropy())
		c.tick(5 * time.Millisecond)
		tr.Rename(p, p+".locked")
	}
	if last <= first {
		t.Fatalf("tarpit did not escalate: first=%v last=%v", first, last)
	}
	// Once confirmed, the tarpit should be substantial (measured in seconds by
	// default), which is what starves a cryptor of throughput.
	if last < time.Second {
		t.Fatalf("confirmed tarpit too weak: %v", last)
	}
	if !tr.Verdict().Confirmed {
		t.Fatal("a full encrypting sweep should confirm")
	}
	if tr.Metrics().TarpitTotal <= 0 {
		t.Fatal("expected accumulated tarpit time")
	}
}

func highEntropy() []byte {
	buf := make([]byte, 2048)
	rand.Read(buf)
	return buf
}

// TestReportableMetrics is the measurement the research writeup depends on:
// given a fixed cryptor behaviour, the trap reports a stable, meaningful
// detection latency. It documents the defence's effectiveness numerically.
func TestReportableMetrics(t *testing.T) {
	tr, c := newTestTrap(t, nil)
	targets := walkFiles(tr, "/")
	totalOps := len(targets) * 3 // read + write + rename per file
	for _, p := range targets {
		encryptLike(tr, c, p)
	}
	m := tr.Metrics()
	if !m.Confirmed {
		t.Fatal("expected confirmation within a full share sweep")
	}
	if m.FirstSignalOps == 0 || m.FirstSignalOps > m.ConfirmOps {
		t.Fatalf("nonsensical latency: first-signal=%d confirm=%d", m.FirstSignalOps, m.ConfirmOps)
	}
	// Confirmation must come before the cryptor finishes the share — the files
	// it had not reached yet are the ones the snapshot + tarpit save.
	if m.ConfirmOps >= int64(totalOps) {
		t.Fatalf("confirmed too late (%d of %d ops) to save any files", m.ConfirmOps, totalOps)
	}
	t.Logf("METRICS ops=%d first-signal@%d confirm@%d files-touched=%d score=%d tarpit=%v",
		m.OpsSeen, m.FirstSignalOps, m.ConfirmOps, m.FilesTouched, m.Score, m.TarpitTotal)
}
