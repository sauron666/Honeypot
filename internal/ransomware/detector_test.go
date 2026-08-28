package ransomware

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func textBytes(n int) []byte {
	const sample = "This document sets out the quarterly revenue position for the finance " +
		"department and should be treated as confidential. "
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(sample)
	}
	return []byte(b.String()[:n])
}

// clock returns a deterministic time source.
func clock(start time.Time, step time.Duration) (func() time.Time, func(time.Duration)) {
	now := start
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

func newDetector(now func() time.Time) *Detector {
	o := DefaultOptions()
	o.Now = now
	return New(o)
}

func TestEntropyDistinguishesTextFromRandom(t *testing.T) {
	if e := Entropy(textBytes(4096)); e > 5.5 {
		t.Errorf("English text entropy = %.2f, expected well under 5.5", e)
	}
	if e := Entropy(randomBytes(4096)); e < 7.9 {
		t.Errorf("random data entropy = %.2f, expected close to 8", e)
	}
	if e := Entropy(nil); e != 0 {
		t.Errorf("empty input entropy = %v", e)
	}
}

func TestBenignActivityDoesNotTrigger(t *testing.T) {
	// Someone browsing the share and saving a document must not look like an
	// encryptor, or the detection is worthless.
	now, advance := clock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), time.Second)
	d := newDetector(now)

	for i := 0; i < 6; i++ {
		d.Observe(Op{Kind: OpRead, Path: fmt.Sprintf("/srv/backup/finance/report-%d.docx", i)})
		advance(3 * time.Second)
	}
	content := append([]byte("PK\x03\x04"), textBytes(4096)...)
	d.Observe(Op{Kind: OpWrite, Path: "/srv/backup/finance/report-0.docx",
		Content: content, PriorKind: "zip"})

	v := d.Verdict()
	if v.Confirmed {
		t.Fatalf("normal use was called ransomware: %+v", v)
	}
	if v.Score != 0 {
		t.Fatalf("normal use scored %d, want 0", v.Score)
	}
	if d.Tarpit() != 0 {
		t.Fatal("normal use must not be slowed down")
	}
}

func TestArchiveUploadAloneDoesNotTrigger(t *testing.T) {
	// A .zip is legitimately indistinguishable from encrypted data. Flagging on
	// entropy alone would fire on every backup that lands on the share.
	now, _ := clock(time.Now(), time.Second)
	d := newDetector(now)
	d.Observe(Op{Kind: OpWrite, Path: "/srv/backup/nightly.zip", Content: randomBytes(8192)})

	if v := d.Verdict(); v.Score != 0 {
		t.Fatalf("a plain archive upload scored %d: %+v", v.Score, v)
	}
}

func TestFullEncryptorRunIsConfirmed(t *testing.T) {
	now, advance := clock(time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC), 0)
	d := newDetector(now)

	files := []string{
		"!!!_payroll_2026.xlsx", "AAA_contracts.docx", "invoices-2025.pdf",
		"personnel.docx", "budget.xlsx", "audit.pdf", "policies.docx",
		"salaries.xlsx", "tax-returns.pdf", "board-minutes.docx",
		"forecast.xlsx", "legal-opinion.pdf", "nda.docx", "payments.xlsx",
	}

	var confirmed bool
	var findings []Finding
	for i, name := range files {
		p := "/srv/backup/finance/" + name
		// Read the original, write random data over it, then rename it.
		findings = append(findings, d.Observe(Op{Kind: OpRead, Path: p, Canary: i < 2})...)
		advance(80 * time.Millisecond)
		findings = append(findings, d.Observe(Op{
			Kind: OpWrite, Path: p, Content: randomBytes(4096),
			PriorKind: "zip", Canary: i < 2,
		})...)
		advance(80 * time.Millisecond)
		findings = append(findings, d.Observe(Op{
			Kind: OpRename, Path: p, NewPath: p + ".locked",
		})...)
		advance(80 * time.Millisecond)
		if d.Verdict().Confirmed && !confirmed {
			confirmed = true
			if i > 5 {
				t.Errorf("took %d files to confirm; an encryptor should be caught in the first few", i+1)
			}
		}
	}

	v := d.Verdict()
	if !v.Confirmed {
		t.Fatalf("a textbook encryptor run was not confirmed: %+v", v)
	}

	kinds := map[SignalKind]bool{}
	for _, f := range findings {
		kinds[f.Kind] = true
	}
	for _, want := range []SignalKind{
		SignalEntropy, SignalMagicLoss, SignalExtension, SignalVelocity, SignalCanary, SignalConfirmed,
	} {
		if !kinds[want] {
			t.Errorf("signal %s never fired", want)
		}
	}
	if len(v.Extensions) == 0 || v.Extensions[0] != ".locked" {
		t.Errorf("the new extension was not recorded: %v", v.Extensions)
	}
	// Once confirmed the tarpit must actually bite.
	if delay := d.Tarpit(); delay < time.Second {
		t.Errorf("tarpit delay after confirmation = %s, too short to buy any time", delay)
	}
}

func TestEachSignalScoresOnlyOnce(t *testing.T) {
	// A thousand encrypted writes are one detection, not a thousand; otherwise
	// the score is just a byte counter.
	now, advance := clock(time.Now(), 0)
	d := newDetector(now)

	for i := 0; i < 50; i++ {
		d.Observe(Op{
			Kind: OpWrite, Path: fmt.Sprintf("/srv/f%d.docx", i),
			Content: randomBytes(2048), PriorKind: "zip",
		})
		advance(50 * time.Millisecond)
	}
	// entropy + magic loss + velocity, each once.
	if v := d.Verdict(); v.Score > 70 {
		t.Fatalf("score %d suggests a signal was counted repeatedly", v.Score)
	}
}

func TestRansomNoteIsCapturedWithContacts(t *testing.T) {
	now, _ := clock(time.Now(), 0)
	d := newDetector(now)

	note := `!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!

To recover your data contact us:
  email: recovery.team@protonmail.example
  tox: 4A5B6C7D8E9F0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
  onion: xy7kj3mnbvcxz2qwertyuiop45672asdfghjkl3mnbvcxz2qwerty456.onion

Personal ID: A93F-2210-CCE1-99AB

Payment: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Do not contact the police.`

	findings := d.Observe(Op{
		Kind: OpWrite, Path: "/srv/backup/finance/HOW_TO_DECRYPT_FILES.txt",
		Content: []byte(note),
	})

	var noteFinding *Finding
	for i := range findings {
		if findings[i].Kind == SignalNote {
			noteFinding = &findings[i]
		}
	}
	if noteFinding == nil {
		t.Fatal("the ransom note was not recognised")
	}
	contacts, _ := noteFinding.Evidence["contacts"].(map[string][]string)
	if contacts == nil {
		t.Fatal("no contacts were extracted from the note")
	}
	for _, want := range []string{"email", "onion", "bitcoin", "tox", "victim_id"} {
		if len(contacts[want]) == 0 {
			t.Errorf("no %s extracted from the note", want)
		}
	}
	if got := contacts["bitcoin"][0]; got != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("bitcoin address = %q", got)
	}
	if d.Verdict().Note == "" {
		t.Error("the note text must be kept: it is evidence and it names the family")
	}
}

func TestCanaryTouchAloneIsNotEnoughToConfirm(t *testing.T) {
	// A canary read is a strong signal but not proof of encryption; confirming
	// on it alone would misreport an attacker who merely browsed the share.
	now, _ := clock(time.Now(), 0)
	d := newDetector(now)
	d.Observe(Op{Kind: OpRead, Path: "/srv/backup/!!!_payroll.xlsx", Canary: true})

	v := d.Verdict()
	if v.Confirmed {
		t.Fatal("a single canary read must not confirm ransomware")
	}
	if v.Score == 0 {
		t.Fatal("a canary touch must still raise suspicion")
	}
	if d.Tarpit() == 0 {
		t.Fatal("suspicion should already slow the caller a little")
	}
}

func TestTarpitGrowsWithSuspicionAndIsCapped(t *testing.T) {
	now, advance := clock(time.Now(), 0)
	o := DefaultOptions()
	o.Now = now
	o.TarpitMax = 2 * time.Second
	d := New(o)

	var last time.Duration
	for i := 0; i < 30; i++ {
		d.Observe(Op{
			Kind: OpWrite, Path: fmt.Sprintf("/srv/f%d.docx", i),
			Content: randomBytes(2048), PriorKind: "zip", Canary: i == 0,
		})
		d.Observe(Op{Kind: OpRename, Path: fmt.Sprintf("/srv/f%d.docx", i),
			NewPath: fmt.Sprintf("/srv/f%d.docx.crypt", i)})
		advance(50 * time.Millisecond)

		got := d.Tarpit()
		if got < last {
			t.Fatalf("tarpit went backwards: %s then %s", last, got)
		}
		last = got
	}
	if last > o.TarpitMax {
		t.Fatalf("tarpit %s exceeds the configured maximum %s", last, o.TarpitMax)
	}
	if last < time.Second {
		t.Fatalf("a confirmed encryptor is only slowed by %s", last)
	}
}

func TestSniffKind(t *testing.T) {
	cases := map[string][]byte{
		"zip":     []byte("PK\x03\x04rest"),
		"pdf":     []byte("%PDF-1.7 rest"),
		"png":     []byte("\x89PNG\r\n\x1a\nrest"),
		"elf":     []byte("\x7fELFrest"),
		"gzip":    {0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4},
		"text":    []byte("hello, this is a plain text document\n"),
		"unknown": randomBytes(64),
	}
	for want, in := range cases {
		if got := SniffKind(in); got != want {
			t.Errorf("SniffKind(%s) = %q, want %q", want, got, want)
		}
	}
}

func TestRenameWithoutAppendedSuffixIsIgnored(t *testing.T) {
	// Ordinary renames happen. Only the append-a-suffix pattern is the tell.
	now, _ := clock(time.Now(), 0)
	d := newDetector(now)
	for i := 0; i < 10; i++ {
		d.Observe(Op{
			Kind:    OpRename,
			Path:    fmt.Sprintf("/srv/draft-%d.docx", i),
			NewPath: fmt.Sprintf("/srv/final-%d.docx", i),
		})
	}
	if v := d.Verdict(); len(v.Extensions) != 0 {
		t.Fatalf("plain renames were treated as an extension change: %v", v.Extensions)
	}
}

func TestConcurrentObserveIsSafe(t *testing.T) {
	now, _ := clock(time.Now(), 0)
	d := newDetector(now)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 50; i++ {
				d.Observe(Op{
					Kind: OpWrite, Path: fmt.Sprintf("/srv/g%d-f%d.docx", g, i),
					Content: randomBytes(1024), PriorKind: "zip",
				})
				d.Tarpit()
				d.Verdict()
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	if v := d.Verdict(); v.FilesTouched != 400 {
		t.Fatalf("files touched = %d, want 400", v.FilesTouched)
	}
}
