// Package fusetrap is a hypervisor-agnostic ransomware trap.
//
// The DRAKVUF observer sees an attacker's every move, but it only runs on Xen
// with a VMFUNC-capable CPU. Most estates run KVM/Proxmox, VMware or Hyper-V,
// where agentless VMI is not available. This package closes that gap for the
// one threat that matters most — ransomware — without caring what runs the VM.
//
// The idea: MIRAGE serves a juicy network share (finance, backups, HR) from a
// userspace filesystem. Any full-OS decoy, on any hypervisor, can mount it;
// so can a real endpoint reached over the wire. Every file operation on that
// share passes through this trap before it touches the backing store, so:
//
//   - each write feeds the ransomware detector (entropy, magic-loss, velocity,
//     canary, note) — the same engine the FTP service uses;
//   - the trap TARPITS: it delays each operation by a duration that grows with
//     suspicion, so ordinary browsing is instant but a cryptor is throttled to
//     a crawl, buying time and saving the files it has not reached yet;
//   - on confirmation the trap fires a callback the app wires to a snapshot
//     (preserve the crime scene on the real hypervisor) and a critical alert.
//
// Nothing here is Xen-specific and nothing runs inside the guest, so the same
// protection holds on every platform. The FUSE binding that mounts this over a
// real kernel lives in fs_linux.go; this file is the portable brain, which is
// why it is exercised by tests on every platform without a kernel at all.
package fusetrap

import (
	"path"
	"sort"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/ransomware"
)

// Metrics is the measurable outcome of a trap session. The point of the tarpit
// is not just to detect but to LIMIT damage, so the numbers that matter are
// how fast we were sure and how much we throttled — these are what a rigorous
// evaluation of the defence reports.
type Metrics struct {
	OpsSeen        int64         `json:"ops_seen"`
	WritesSeen     int64         `json:"writes_seen"`
	FilesTouched   int           `json:"files_touched"`
	CanaryHits     int64         `json:"canary_hits"`
	FirstSignalAt  time.Time     `json:"first_signal_at,omitempty"`
	ConfirmedAt    time.Time     `json:"confirmed_at,omitempty"`
	FirstSignalOps int64         `json:"first_signal_ops"` // ops until the first signal
	ConfirmOps     int64         `json:"confirm_ops"`      // ops until confirmation
	TarpitTotal    time.Duration `json:"tarpit_total"`     // wall-clock delay imposed
	Confirmed      bool          `json:"confirmed"`
	Score          int           `json:"score"`
}

// Event is a single thing the trap wants the outside world to know: a detector
// finding, or the confirmation. The app turns these into evidence-chain events,
// engagement signals and alerts.
type Event struct {
	At        time.Time
	Finding   ransomware.Finding
	Confirmed bool
	Verdict   ransomware.Verdict
	Metrics   Metrics
}

// Options configures a trap.
type Options struct {
	// ShareID names this share in events (e.g. "fileserver-finance").
	ShareID string
	// Detector options; zero values fall back to ransomware.DefaultOptions.
	Detector ransomware.Options
	// SampleBytes is how many bytes of each write to feed the entropy check.
	// Whole files are never buffered — a few kilobytes settle the entropy.
	SampleBytes int
	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
	// OnEvent receives findings and the confirmation. Never nil in production;
	// may be nil in tests. Called without the trap lock held.
	OnEvent func(Event)
	// OnConfirmed fires exactly once, when ransomware is confirmed. The app
	// wires it to compute.Snapshot (preserve the scene) and the alert path.
	// Called without the trap lock held.
	OnConfirmed func(Verdict ransomware.Verdict, m Metrics)
}

const defaultSampleBytes = 4096

// Trap is the portable ransomware trap: an in-memory decoy filesystem plus the
// detector, tarpit and metrics. The FUSE layer calls its file methods; tests
// call them directly.
type Trap struct {
	mu           sync.Mutex
	opts         Options
	det          *ransomware.Detector
	root         *node
	now          func() time.Time
	m            Metrics
	confirmFired bool
}

// New builds a trap with a realistic decoy tree already populated.
func New(opts Options) *Trap {
	if opts.SampleBytes <= 0 {
		opts.SampleBytes = defaultSampleBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Detector.Now == nil {
		opts.Detector.Now = opts.Now
	}
	t := &Trap{
		opts: opts,
		det:  ransomware.New(opts.Detector),
		root: newDir(),
		now:  opts.Now,
	}
	t.seed()
	return t
}

// Metrics returns a snapshot of the current session metrics.
func (t *Trap) Metrics() Metrics {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.m
	v := t.det.Verdict()
	m.FilesTouched = v.FilesTouched
	m.Score = v.Score
	m.Confirmed = v.Confirmed
	return m
}

// Verdict exposes the detector's current belief.
func (t *Trap) Verdict() ransomware.Verdict { return t.det.Verdict() }

// ---------------------------------------------------------------------------
// The in-memory decoy filesystem
// ---------------------------------------------------------------------------

type node struct {
	dir       bool
	data      []byte
	children  map[string]*node
	canary    bool
	mtime     time.Time
	priorKind string // remembered file kind, to detect in-place encryption
}

func newDir() *node  { return &node{dir: true, children: map[string]*node{}} }
func newFile() *node { return &node{} }

// resolve walks a slash-separated path to its node. Returns nil if missing.
func (t *Trap) resolve(p string) *node {
	n := t.root
	for _, part := range splitPath(p) {
		if n == nil || !n.dir {
			return nil
		}
		n = n.children[part]
	}
	return n
}

// parentOf returns the directory node holding p, and the leaf name.
func (t *Trap) parentOf(p string) (*node, string) {
	parts := splitPath(p)
	if len(parts) == 0 {
		return nil, ""
	}
	n := t.root
	for _, part := range parts[:len(parts)-1] {
		if n == nil || !n.dir {
			return nil, ""
		}
		n = n.children[part]
	}
	return n, parts[len(parts)-1]
}

func splitPath(p string) []string {
	p = path.Clean("/" + p)
	if p == "/" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range p[1:] {
		if r == '/' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// ---------------------------------------------------------------------------
// File operations — each records an Op, runs the detector, and returns the
// tarpit delay the caller must impose before completing the operation.
// ---------------------------------------------------------------------------

// Write records a write to p and returns the delay to impose. The content is
// the bytes being written (a sample is enough); the backing store is updated
// so a cryptor sees its own ciphertext, which keeps the ruse convincing.
func (t *Trap) Write(p string, content []byte) time.Duration {
	t.mu.Lock()
	n := t.resolve(p)
	created := false
	if n == nil {
		parent, name := t.parentOf(p)
		if parent == nil || !parent.dir {
			t.mu.Unlock()
			return 0
		}
		n = newFile()
		parent.children[name] = n
		created = true
	}
	prior := n.priorKind
	sample := content
	if len(sample) > t.opts.SampleBytes {
		sample = sample[:t.opts.SampleBytes]
	}
	// Update backing store and remember the new file kind.
	n.data = append(n.data[:0], content...)
	n.mtime = t.now()
	n.priorKind = ransomware.SniffKind(sample)
	kind := ransomware.OpWrite
	if created {
		kind = ransomware.OpCreate
	}
	op := ransomware.Op{
		Kind: kind, Path: p, Content: sample,
		Size: int64(len(content)), At: t.now(),
		PriorKind: prior, Canary: n.canary,
	}
	t.m.WritesSeen++
	return t.observeLocked(op)
}

// WriteAt patches the backing store at an offset (the FUSE write path, which
// delivers a file in chunks) and returns the tarpit delay. The written chunk
// is the entropy sample — a cryptor's chunks are already ciphertext.
func (t *Trap) WriteAt(p string, data []byte, off int64) time.Duration {
	t.mu.Lock()
	n := t.resolve(p)
	created := false
	if n == nil {
		parent, name := t.parentOf(p)
		if parent == nil || !parent.dir {
			t.mu.Unlock()
			return 0
		}
		n = newFile()
		parent.children[name] = n
		created = true
	}
	prior := n.priorKind
	end := off + int64(len(data))
	if int64(len(n.data)) < end {
		grown := make([]byte, end)
		copy(grown, n.data)
		n.data = grown
	}
	copy(n.data[off:end], data)
	n.mtime = t.now()
	sample := data
	if len(sample) > t.opts.SampleBytes {
		sample = sample[:t.opts.SampleBytes]
	}
	n.priorKind = ransomware.SniffKind(sample)
	kind := ransomware.OpWrite
	if created {
		kind = ransomware.OpCreate
	}
	op := ransomware.Op{
		Kind: kind, Path: p, Content: sample,
		Size: int64(len(n.data)), At: t.now(),
		PriorKind: prior, Canary: n.canary,
	}
	t.m.WritesSeen++
	return t.observeLocked(op)
}

// Create makes an empty file at p (the FUSE create path) and records it.
func (t *Trap) Create(p string) time.Duration {
	return t.WriteAt(p, nil, 0)
}

// Mkdir creates a directory at p. It records nothing: making a folder is not a
// ransomware signal on its own.
func (t *Trap) Mkdir(p string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	parent, name := t.parentOf(p)
	if parent == nil || !parent.dir {
		return false
	}
	if _, ok := parent.children[name]; ok {
		return false
	}
	parent.children[name] = newDir()
	return true
}

// Size returns the byte length of a file (for FUSE getattr).
func (t *Trap) Size(p string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.resolve(p)
	if n == nil || n.dir {
		return 0
	}
	return int64(len(n.data))
}

// Read records a read and returns the delay. Reads feed velocity and canary.
func (t *Trap) Read(p string) time.Duration {
	t.mu.Lock()
	n := t.resolve(p)
	if n == nil || n.dir {
		t.mu.Unlock()
		return 0
	}
	op := ransomware.Op{Kind: ransomware.OpRead, Path: p, At: t.now(), Canary: n.canary}
	return t.observeLocked(op)
}

// Rename records a rename (the classic ".locked" mass-extension change) and
// returns the delay.
func (t *Trap) Rename(from, to string) time.Duration {
	t.mu.Lock()
	fp, fn := t.parentOf(from)
	tp, tn := t.parentOf(to)
	var canary bool
	if fp != nil {
		if n := fp.children[fn]; n != nil {
			canary = n.canary
			if tp != nil {
				tp.children[tn] = n
			}
			delete(fp.children, fn)
		}
	}
	op := ransomware.Op{Kind: ransomware.OpRename, Path: from, NewPath: to, At: t.now(), Canary: canary}
	return t.observeLocked(op)
}

// Delete records a delete and returns the delay.
func (t *Trap) Delete(p string) time.Duration {
	t.mu.Lock()
	parent, name := t.parentOf(p)
	var canary bool
	if parent != nil {
		if n := parent.children[name]; n != nil {
			canary = n.canary
		}
		delete(parent.children, name)
	}
	op := ransomware.Op{Kind: ransomware.OpDelete, Path: p, At: t.now(), Canary: canary}
	return t.observeLocked(op)
}

// observeLocked runs the detector for op, updates metrics, fires events, and
// returns the tarpit delay. Called with t.mu held; releases it before firing
// callbacks so a slow sink never blocks the filesystem.
func (t *Trap) observeLocked(op ransomware.Op) time.Duration {
	t.m.OpsSeen++
	if op.Canary {
		t.m.CanaryHits++
	}
	findings := t.det.Observe(op)
	delay := t.det.Tarpit()
	v := t.det.Verdict()

	if len(findings) > 0 && t.m.FirstSignalAt.IsZero() {
		t.m.FirstSignalAt = op.At
		t.m.FirstSignalOps = t.m.OpsSeen
	}
	newlyConfirmed := false
	for _, f := range findings {
		if f.Kind == ransomware.SignalConfirmed && !t.confirmFired {
			t.confirmFired = true
			newlyConfirmed = true
			t.m.ConfirmedAt = op.At
			t.m.ConfirmOps = t.m.OpsSeen
		}
	}
	t.m.TarpitTotal += delay
	m := t.m
	m.FilesTouched = v.FilesTouched
	m.Score = v.Score
	m.Confirmed = v.Confirmed
	onEvent := t.opts.OnEvent
	onConfirmed := t.opts.OnConfirmed
	t.mu.Unlock()

	// Fire callbacks without the lock.
	if onEvent != nil {
		for _, f := range findings {
			onEvent(Event{At: op.At, Finding: f, Confirmed: f.Kind == ransomware.SignalConfirmed, Verdict: v, Metrics: m})
		}
	}
	if newlyConfirmed && onConfirmed != nil {
		onConfirmed(v, m)
	}
	return delay
}

// ---------------------------------------------------------------------------
// Listing (read-only introspection for the FUSE layer and the API)
// ---------------------------------------------------------------------------

// Entry describes one child in a directory listing.
type Entry struct {
	Name   string
	Dir    bool
	Size   int64
	Canary bool
}

// List returns the sorted children of directory p (empty if missing).
func (t *Trap) List(p string) []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.resolve(p)
	if n == nil || !n.dir {
		return nil
	}
	out := make([]Entry, 0, len(n.children))
	for name, c := range n.children {
		out = append(out, Entry{Name: name, Dir: c.dir, Size: int64(len(c.data)), Canary: c.canary})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Content returns a copy of the file's current bytes (for the FUSE read path).
func (t *Trap) Content(p string) ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.resolve(p)
	if n == nil || n.dir {
		return nil, false
	}
	return append([]byte(nil), n.data...), true
}

// IsDir reports whether p is a directory.
func (t *Trap) IsDir(p string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.resolve(p)
	return n != nil && n.dir
}

// Exists reports whether p resolves to any node.
func (t *Trap) Exists(p string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resolve(p) != nil
}
