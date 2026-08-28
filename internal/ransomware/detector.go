// Package ransomware detects an encryptor at work on a decoy file share, and
// slows it down while it is happening.
//
// The detection problem is not "did a file change" -- files change constantly.
// It is telling a backup job from an encryptor. Six independent signals are
// combined here, because any one of them alone has a plausible benign
// explanation and all six together have none:
//
//	entropy      encrypted content is indistinguishable from random
//	magic loss   a .docx that stops being a ZIP was rewritten, not edited
//	extension    mass renames appending a new suffix
//	velocity     files touched per second, across distinct paths
//	canary       bait files touched in the order a directory sweep produces
//	note         a ransom note appearing in a directory being swept
//
// On a decoy there is no legitimate writer at all, so the thresholds can be
// tighter than any product could dare on a production share.
package ransomware

import (
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// OpKind is a file operation.
type OpKind string

const (
	OpRead   OpKind = "read"
	OpWrite  OpKind = "write"
	OpRename OpKind = "rename"
	OpDelete OpKind = "delete"
	OpCreate OpKind = "create"
)

// Op is one observed file operation.
type Op struct {
	Kind    OpKind
	Path    string
	NewPath string // for renames
	// Content is a sample of what was written. Only the first few kilobytes
	// matter for entropy, so callers should not buffer whole files for this.
	Content []byte
	Size    int64
	At      time.Time
	// PriorKind is the file type the path had before this write, when known.
	// Losing it is strong evidence of in-place encryption.
	PriorKind string
	// Canary marks a bait file that no legitimate process should touch.
	Canary bool
}

// SignalKind identifies one detection signal.
type SignalKind string

const (
	SignalEntropy   SignalKind = "high-entropy-write"
	SignalMagicLoss SignalKind = "file-type-destroyed"
	SignalExtension SignalKind = "mass-extension-change"
	SignalVelocity  SignalKind = "write-velocity"
	SignalCanary    SignalKind = "canary-touched"
	SignalNote      SignalKind = "ransom-note"
	SignalConfirmed SignalKind = "ransomware-confirmed"
)

// Finding is something worth telling the operator about.
type Finding struct {
	Kind    SignalKind
	Message string
	// Score is how much this contributes to the overall verdict, 0-100.
	Score    int
	Path     string
	Evidence map[string]any
}

// Verdict summarises the detector's current belief.
type Verdict struct {
	Score        int
	Confirmed    bool
	FilesTouched int
	Extensions   []string
	Note         string
	FirstSeen    time.Time
	LastSeen     time.Time
}

// Options tunes the detector.
type Options struct {
	// EntropyThreshold in bits per byte. Encrypted and compressed data both sit
	// above 7.5; the magic-byte and extension signals separate them.
	EntropyThreshold float64
	// MinEntropySample is the smallest write worth measuring: short writes have
	// unstable entropy and produce false positives.
	MinEntropySample int
	// VelocityFiles over VelocityWindow triggers the velocity signal.
	VelocityFiles  int
	VelocityWindow time.Duration
	// ConfirmScore is the total at which the detector declares ransomware.
	ConfirmScore int
	// TarpitMax is the longest delay the tarpit will impose on one operation.
	TarpitMax time.Duration
	Now       func() time.Time
}

// DefaultOptions are tuned for a decoy share, where any writer is hostile.
func DefaultOptions() Options {
	return Options{
		EntropyThreshold: 7.5,
		MinEntropySample: 512,
		VelocityFiles:    12,
		VelocityWindow:   10 * time.Second,
		ConfirmScore:     70,
		TarpitMax:        8 * time.Second,
		Now:              time.Now,
	}
}

// Detector accumulates evidence across the operations of one session.
type Detector struct {
	mu   sync.Mutex
	opts Options

	score      int
	confirmed  bool
	touched    map[string]bool
	newExts    map[string]int
	recent     []time.Time
	firstSeen  time.Time
	lastSeen   time.Time
	noteText   string
	fired      map[SignalKind]bool
	canaryHits int
}

// New builds a detector.
func New(opts Options) *Detector {
	d := DefaultOptions()
	if opts.EntropyThreshold > 0 {
		d.EntropyThreshold = opts.EntropyThreshold
	}
	if opts.MinEntropySample > 0 {
		d.MinEntropySample = opts.MinEntropySample
	}
	if opts.VelocityFiles > 0 {
		d.VelocityFiles = opts.VelocityFiles
	}
	if opts.VelocityWindow > 0 {
		d.VelocityWindow = opts.VelocityWindow
	}
	if opts.ConfirmScore > 0 {
		d.ConfirmScore = opts.ConfirmScore
	}
	if opts.TarpitMax > 0 {
		d.TarpitMax = opts.TarpitMax
	}
	if opts.Now != nil {
		d.Now = opts.Now
	}
	return &Detector{
		opts: d, touched: map[string]bool{}, newExts: map[string]int{},
		fired: map[SignalKind]bool{},
	}
}

// Observe folds one operation in and returns any new findings.
func (d *Detector) Observe(op Op) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()

	if op.At.IsZero() {
		op.At = d.opts.Now()
	}
	if d.firstSeen.IsZero() {
		d.firstSeen = op.At
	}
	d.lastSeen = op.At

	var findings []Finding
	add := func(f Finding) {
		// Each signal contributes its score once. A thousand encrypted writes
		// are one detection, not a thousand.
		if !d.fired[f.Kind] {
			d.fired[f.Kind] = true
			d.score += f.Score
		}
		findings = append(findings, f)
	}

	switch op.Kind {
	case OpWrite, OpCreate:
		d.touched[op.Path] = true
		d.recent = append(d.recent, op.At)

		if f, ok := d.checkNote(op); ok {
			add(f)
		}
		if f, ok := d.checkEntropy(op); ok {
			add(f)
		}
		if f, ok := d.checkMagicLoss(op); ok {
			add(f)
		}

	case OpRename:
		d.touched[op.Path] = true
		d.recent = append(d.recent, op.At)
		if f, ok := d.checkExtension(op); ok {
			add(f)
		}

	case OpDelete:
		d.touched[op.Path] = true
		d.recent = append(d.recent, op.At)

	case OpRead:
		// Reads alone are not encryption, but an encryptor reads every file it
		// rewrites, so they count towards velocity.
		d.recent = append(d.recent, op.At)
	}

	if op.Canary {
		d.canaryHits++
		if d.canaryHits == 1 {
			add(Finding{
				Kind: SignalCanary, Score: 25, Path: op.Path,
				Message:  "a canary file was touched: no legitimate process reads or writes it",
				Evidence: map[string]any{"path": op.Path, "operation": string(op.Kind)},
			})
		}
	}

	if f, ok := d.checkVelocity(op.At); ok {
		add(f)
	}

	if !d.confirmed && d.score >= d.opts.ConfirmScore {
		d.confirmed = true
		findings = append(findings, Finding{
			Kind:  SignalConfirmed,
			Score: 0, // the confirmation is a conclusion, not more evidence
			Message: "ransomware confirmed on a decoy share: " +
				strings.Join(d.reasonsLocked(), ", "),
			Evidence: map[string]any{
				"score":         d.score,
				"files_touched": len(d.touched),
				"extensions":    d.extensionsLocked(),
				"ransom_note":   d.noteText,
				"elapsed":       d.lastSeen.Sub(d.firstSeen).String(),
			},
		})
	}
	return findings
}

func (d *Detector) checkEntropy(op Op) (Finding, bool) {
	if len(op.Content) < d.opts.MinEntropySample {
		return Finding{}, false
	}
	e := Entropy(op.Content)
	if e < d.opts.EntropyThreshold {
		return Finding{}, false
	}
	// Archives and media are legitimately high entropy. Only flag when the
	// destination did not already hold compressed data.
	if isCompressedPath(op.Path) && op.PriorKind == "" {
		return Finding{}, false
	}
	return Finding{
		Kind: SignalEntropy, Score: 25, Path: op.Path,
		Message: "write of near-random data: content indistinguishable from encryption",
		Evidence: map[string]any{
			"path": op.Path, "entropy_bits_per_byte": round2(e),
			"threshold": d.opts.EntropyThreshold, "sample_bytes": len(op.Content),
		},
	}, true
}

func (d *Detector) checkMagicLoss(op Op) (Finding, bool) {
	if op.PriorKind == "" || len(op.Content) < 8 {
		return Finding{}, false
	}
	now := SniffKind(op.Content)
	if now == op.PriorKind {
		return Finding{}, false
	}
	return Finding{
		Kind: SignalMagicLoss, Score: 25, Path: op.Path,
		Message: "a file lost its type in place: it was rewritten, not edited",
		Evidence: map[string]any{
			"path": op.Path, "was": op.PriorKind, "now": now,
		},
	}, true
}

var suffixRe = regexp.MustCompile(`\.[A-Za-z0-9_-]{2,12}$`)

func (d *Detector) checkExtension(op Op) (Finding, bool) {
	if op.NewPath == "" {
		return Finding{}, false
	}
	oldExt := path.Ext(op.Path)
	newExt := path.Ext(op.NewPath)
	if newExt == "" || newExt == oldExt {
		return Finding{}, false
	}
	// The tell is a suffix appended to the whole old name, which is how almost
	// every family marks its work: report.docx -> report.docx.locked
	appended := strings.HasPrefix(path.Base(op.NewPath), path.Base(op.Path)) ||
		suffixRe.MatchString(op.NewPath)
	if !appended {
		return Finding{}, false
	}
	d.newExts[newExt]++
	if d.newExts[newExt] < 3 {
		return Finding{}, false
	}
	return Finding{
		Kind: SignalExtension, Score: 25, Path: op.NewPath,
		Message: "files are being renamed with a common new extension " + newExt,
		Evidence: map[string]any{
			"extension": newExt, "count": d.newExts[newExt],
			"example": op.Path + " -> " + op.NewPath,
		},
	}, true
}

func (d *Detector) checkVelocity(at time.Time) (Finding, bool) {
	cutoff := at.Add(-d.opts.VelocityWindow)
	keep := d.recent[:0]
	for _, t := range d.recent {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	d.recent = keep
	if len(d.recent) < d.opts.VelocityFiles {
		return Finding{}, false
	}
	return Finding{
		Kind: SignalVelocity, Score: 15,
		Message: "file operations far above any human or backup rate",
		Evidence: map[string]any{
			"operations": len(d.recent), "window": d.opts.VelocityWindow.String(),
		},
	}, true
}

// ransomNoteNames are the filenames families leave behind. The list is
// deliberately about shape rather than any particular family: a new one will
// still be called something like this.
var ransomNoteNames = []string{
	"readme", "read_me", "how_to", "howto", "decrypt", "restore",
	"recover", "unlock", "your_files", "ransom", "important",
}

func (d *Detector) checkNote(op Op) (Finding, bool) {
	base := strings.ToLower(path.Base(op.Path))
	ext := path.Ext(base)
	if ext != ".txt" && ext != ".html" && ext != ".hta" && ext != ".md" && ext != "" {
		return Finding{}, false
	}
	matched := ""
	for _, n := range ransomNoteNames {
		if strings.Contains(base, n) {
			matched = n
			break
		}
	}
	if matched == "" {
		return Finding{}, false
	}
	text := string(op.Content)
	if len(text) > 8192 {
		text = text[:8192]
	}
	d.noteText = text
	return Finding{
		Kind: SignalNote, Score: 30, Path: op.Path,
		Message: "a ransom note was written: " + path.Base(op.Path),
		Evidence: map[string]any{
			"path": op.Path, "matched": matched, "note": text,
			// The contact details in the note identify the affiliate, and are
			// what an incident responder needs first.
			"contacts": ExtractContacts(text),
		},
	}, true
}

// Tarpit returns how long the caller should delay this operation.
//
// Slowing an encryptor is the only defensive action a decoy can take that has
// no downside: the files are worthless, and every second bought is a second the
// responders have. The delay grows with suspicion so that ordinary browsing of
// the share stays instant.
func (d *Detector) Tarpit() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.score <= 0 {
		return 0
	}
	// Quadratic in the score, capped: barely noticeable while unsure, brutal
	// once confirmed.
	frac := float64(d.score) / float64(d.opts.ConfirmScore)
	if frac > 2 {
		frac = 2
	}
	delay := time.Duration(frac * frac * float64(d.opts.TarpitMax) / 4)
	if delay > d.opts.TarpitMax {
		delay = d.opts.TarpitMax
	}
	return delay
}

// Verdict reports the current belief.
func (d *Detector) Verdict() Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Verdict{
		Score: d.score, Confirmed: d.confirmed,
		FilesTouched: len(d.touched), Extensions: d.extensionsLocked(),
		Note: d.noteText, FirstSeen: d.firstSeen, LastSeen: d.lastSeen,
	}
}

func (d *Detector) extensionsLocked() []string {
	out := make([]string, 0, len(d.newExts))
	for e := range d.newExts {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func (d *Detector) reasonsLocked() []string {
	var out []string
	for k := range d.fired {
		if k != SignalConfirmed {
			out = append(out, string(k))
		}
	}
	sort.Strings(out)
	return out
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
