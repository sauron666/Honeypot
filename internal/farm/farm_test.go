package farm

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// fakeCompute stands in for libvirt or Proxmox. It records the calls, because
// the order of some of them is the safety property under test.
type fakeCompute struct {
	mu        sync.Mutex
	vms       map[string]*drivers.DecoyStatus
	snapshots map[string][]string
	calls     []string
	failStart bool
	failSnap  bool
}

func newFake() *fakeCompute {
	return &fakeCompute{
		vms:       map[string]*drivers.DecoyStatus{},
		snapshots: map[string][]string{},
	}
}

func (f *fakeCompute) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeCompute) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeCompute) Info() drivers.Info          { return drivers.Info{Name: "fake"} }
func (f *fakeCompute) Probe(context.Context) error { return nil }
func (f *fakeCompute) Close() error                { return nil }

func (f *fakeCompute) Create(_ context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	f.record("create:" + spec.ID)
	f.mu.Lock()
	defer f.mu.Unlock()
	st := drivers.DecoyStatus{ID: spec.ID, Handle: "fake/" + spec.ID,
		State: drivers.StateCreated, CreatedAt: time.Now()}
	f.vms[spec.ID] = &st
	return st, nil
}

func (f *fakeCompute) Start(_ context.Context, id string) error {
	f.record("start:" + id)
	if f.failStart {
		return errors.New("no host capacity")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.vms[id]; ok {
		v.State = drivers.StateRunning
	}
	return nil
}

func (f *fakeCompute) Stop(_ context.Context, id string) error {
	f.record("stop:" + id)
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.vms[id]; ok {
		v.State = drivers.StateStopped
	}
	return nil
}

func (f *fakeCompute) Destroy(_ context.Context, id string) error {
	f.record("destroy:" + id)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vms, id)
	return nil
}

func (f *fakeCompute) Status(_ context.Context, id string) (drivers.DecoyStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.vms[id]; ok {
		return *v, nil
	}
	return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
}

func (f *fakeCompute) List(context.Context) ([]drivers.DecoyStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]drivers.DecoyStatus, 0, len(f.vms))
	for _, v := range f.vms {
		out = append(out, *v)
	}
	return out, nil
}

func (f *fakeCompute) Snapshot(_ context.Context, id, name string) error {
	f.record("snapshot:" + id + ":" + name)
	if f.failSnap {
		return errors.New("no space on the snapshot store")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots[id] = append(f.snapshots[id], name)
	return nil
}

func (f *fakeCompute) Revert(_ context.Context, id, name string) error {
	f.record("revert:" + id + ":" + name)
	return nil
}

// fakeFabric answers the containment question.
type fakeFabric struct {
	violations []string
	err        error
	isolated   []string
	mu         sync.Mutex
}

func (f *fakeFabric) Info() drivers.Info          { return drivers.Info{Name: "fake-fabric"} }
func (f *fakeFabric) Probe(context.Context) error { return nil }
func (f *fakeFabric) Close() error                { return nil }
func (f *fakeFabric) EnsureZones(context.Context, []drivers.Zone) error {
	return nil
}
func (f *fakeFabric) AssertContainment(context.Context) ([]string, error) {
	return f.violations, f.err
}
func (f *fakeFabric) Isolate(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isolated = append(f.isolated, id)
	return nil
}
func (f *fakeFabric) KillSwitch(context.Context, string) error { return nil }

func (f *fakeFabric) wasIsolated(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.isolated {
		if got == id {
			return true
		}
	}
	return false
}

type recorder struct {
	mu     sync.Mutex
	events []*event.Event
}

func (r *recorder) publish(e *event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) saying(substr string) *event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if strings.Contains(e.Message, substr) {
			return e
		}
	}
	return nil
}

func snapshotCapable() drivers.Info {
	return drivers.Info{Name: "fake", Capabilities: []drivers.Capability{
		drivers.CapSnapshot, drivers.CapRevert, drivers.CapFullOS}}
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func build(t *testing.T, opt Options) (*Provisioner, *recorder) {
	t.Helper()
	rec := &recorder{}
	opt.Publish = rec.publish
	opt.Log = quiet()
	p, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return p, rec
}

func specs() []Spec {
	return []Spec{
		{ID: "vm-web01", Persona: "linux/web", Template: "debian12-base",
			Revert: RevertOnEngagementEnd},
		{ID: "vm-dc01", Persona: "windows/dc", Template: "ws2022-base", Revert: RevertNever},
	}
}

func TestFullOSDecoysDoNotStartWithoutVerifiedContainment(t *testing.T) {
	// The whole reason to be careful: a VM an attacker can own is a real host
	// on the customer's network. Nothing starts until somebody has checked.
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable()})

	_, err := p.Reconcile(context.Background(), specs())
	if err == nil {
		t.Fatal("full-OS decoys started with nothing verifying containment")
	}
	if !strings.Contains(err.Error(), "fabric driver") {
		t.Fatalf("the refusal does not say what to do about it: %v", err)
	}
	if len(fake.log()) != 0 {
		t.Fatalf("the backend was touched anyway: %v", fake.log())
	}
}

func TestViolatedContainmentRefusesAndSaysWhy(t *testing.T) {
	fake := newFake()
	fabric := &fakeFabric{violations: []string{"dirty zone can reach 10.0.0.0/8 on tcp/445"}}
	p, rec := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(), Fabric: fabric})

	_, err := p.Reconcile(context.Background(), specs())
	if err == nil {
		t.Fatal("decoys started into a segment that can reach production")
	}
	if !strings.Contains(err.Error(), "tcp/445") {
		t.Fatalf("the violation itself is not in the error: %v", err)
	}
	if e := rec.saying("containment is violated"); e == nil {
		t.Fatal("nothing was recorded; this is exactly the event an auditor asks for")
	} else if e.SeverityID != event.SeverityCritical {
		t.Fatalf("a containment violation was recorded at severity %d", e.SeverityID)
	}
	if len(fake.log()) != 0 {
		t.Fatalf("the backend was touched anyway: %v", fake.log())
	}
}

func TestUnenforcedContainmentIsAllowedButRecorded(t *testing.T) {
	// An operator who has contained the segment by other means can say so. What
	// they cannot do is have it pass silently.
	fake := newFake()
	p, rec := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		ContainmentUnenforced: true})

	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatalf("an explicit acknowledgement should be accepted: %v", err)
	}
	if rec.saying("containment unverified") == nil {
		t.Fatal("running without verified containment left no trace")
	}
}

func TestReconcileCreatesStartsAndBaselines(t *testing.T) {
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})

	changes, err := p.Reconcile(context.Background(), specs())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected two changes, got %+v", changes)
	}
	for _, c := range changes {
		if c.Action != "create" {
			t.Fatalf("%s was %s, want create", c.ID, c.Action)
		}
	}

	// The baseline must be taken after the VM is running, not before: a
	// baseline of a cold image means every reset costs a visible boot.
	calls := fake.log()
	start, snap := -1, -1
	for i, c := range calls {
		if c == "start:vm-web01" {
			start = i
		}
		if c == "snapshot:vm-web01:"+BaselineSnapshot {
			snap = i
		}
	}
	if start < 0 || snap < 0 || snap < start {
		t.Fatalf("baseline was not taken after the decoy was running: %v", calls)
	}

	// A second reconcile is a no-op, and does not take a second baseline.
	changes, err = p.Reconcile(context.Background(), specs())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if c.Action != "unchanged" {
			t.Fatalf("a settled deployment reported %s for %s", c.Action, c.ID)
		}
	}
	if n := strings.Count(strings.Join(fake.log(), " "), BaselineSnapshot); n != 2 {
		t.Fatalf("the baseline was retaken: %d snapshots for 2 decoys", n)
	}
}

func TestReconcileDestroysOnlyWhatItCreated(t *testing.T) {
	fake := newFake()
	// Somebody else's VM, on the same host, with a name MIRAGE never chose.
	fake.vms["prod-billing-01"] = &drivers.DecoyStatus{
		ID: "prod-billing-01", State: drivers.StateRunning}

	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}

	// Drop one decoy from the manifest.
	if _, err := p.Reconcile(context.Background(), specs()[:1]); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(fake.log(), " ")
	if !strings.Contains(joined, "destroy:vm-dc01") {
		t.Fatal("an undeclared decoy of ours was left running")
	}
	if strings.Contains(joined, "destroy:prod-billing-01") {
		t.Fatal("a VM MIRAGE never created was destroyed")
	}
}

func TestRevertKeepsTheDirtyStateFirst(t *testing.T) {
	fake := newFake()
	p, rec := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.calls = nil
	fake.mu.Unlock()

	if err := p.Revert(context.Background(), "vm-web01", "test"); err != nil {
		t.Fatal(err)
	}

	calls := fake.log()
	if len(calls) != 2 {
		t.Fatalf("expected a snapshot then a revert, got %v", calls)
	}
	if !strings.HasPrefix(calls[0], "snapshot:vm-web01:mirage-incident-") {
		t.Fatalf("the attacker's state was not preserved before the reset: %v", calls)
	}
	if calls[1] != "revert:vm-web01:"+BaselineSnapshot {
		t.Fatalf("wrong revert target: %v", calls)
	}
	if rec.saying("reset to baseline") == nil {
		t.Fatal("the reset was not recorded")
	}
}

func TestRevertIsRefusedIfTheDirtyStateCannotBeKept(t *testing.T) {
	// A reset that erases what the attacker installed turns an intrusion into
	// an anecdote. Better to leave the decoy dirty than to lose the evidence.
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	fake.failSnap = true

	err := p.Revert(context.Background(), "vm-web01", "test")
	if err == nil {
		t.Fatal("the decoy was reset with the evidence unsaved")
	}
	if strings.Contains(strings.Join(fake.log(), " "), "revert:vm-web01") {
		t.Fatal("revert ran after the preserving snapshot failed")
	}
}

func TestBurnIsolatesBeforeStoppingAndIsNeverRecycled(t *testing.T) {
	fake := newFake()
	fabric := &fakeFabric{}
	p, rec := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(), Fabric: fabric})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}

	if err := p.Burn(context.Background(), "vm-web01", "attacker gained root"); err != nil {
		t.Fatal(err)
	}
	if !fabric.wasIsolated("vm-web01") {
		t.Fatal("a burned decoy was left on the network")
	}
	if rec.saying("burned and preserved") == nil {
		t.Fatal("the burn was not recorded")
	}

	// Reverting a burned decoy would destroy the evidence.
	if err := p.Revert(context.Background(), "vm-web01", "test"); err == nil {
		t.Fatal("a burned decoy was reverted")
	}
	// And a reconcile must not put an owned host back in front of the attacker.
	changes, err := p.Reconcile(context.Background(), specs())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range changes {
		if c.ID == "vm-web01" {
			found = true
			if c.Action != "skip" {
				t.Fatalf("a burned decoy was %sed back into service", c.Action)
			}
			if !strings.Contains(c.Reason, "attacker gained root") {
				t.Fatalf("the skip does not say why: %q", c.Reason)
			}
		}
	}
	if !found {
		t.Fatal("the burned decoy vanished from the reconcile entirely")
	}
}

func TestABurnedDecoyIsNotDestroyedByRemovingItFromTheManifest(t *testing.T) {
	// Deleting three lines of YAML must not destroy the best forensic artefact
	// the deployment has.
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	if err := p.Burn(context.Background(), "vm-dc01", "attacker gained SYSTEM"); err != nil {
		t.Fatal(err)
	}

	changes, err := p.Reconcile(context.Background(), specs()[:1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(fake.log(), " "), "destroy:vm-dc01") {
		t.Fatal("a burned decoy was destroyed because it left the manifest")
	}
	var skipped bool
	for _, c := range changes {
		if c.ID == "vm-dc01" && c.Action == "skip" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("the operator was not told the decoy was kept: %+v", changes)
	}
}

func TestEngagementEndResetsOnlyWhatThePolicyAsksFor(t *testing.T) {
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.calls = nil
	fake.mu.Unlock()

	p.OnEngagementClosed(context.Background(), []string{"vm-web01", "vm-dc01"})

	joined := strings.Join(fake.log(), " ")
	if !strings.Contains(joined, "revert:vm-web01") {
		t.Fatal("a decoy with revert: on_engagement_end was not reset")
	}
	if strings.Contains(joined, "revert:vm-dc01") {
		t.Fatal("a decoy with revert: never was reset anyway")
	}
}

func TestABackendWithoutSnapshotsStillRuns(t *testing.T) {
	// Podman has no snapshots. A decoy that cannot be reset is still a decoy;
	// refusing to run one would make the abstraction a lie.
	fake := newFake()
	p, _ := build(t, Options{Compute: fake,
		ComputeInfo: drivers.Info{Name: "fake-nosnap"}, Fabric: &fakeFabric{}})

	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(fake.log(), " "), "snapshot:") {
		t.Fatal("a snapshot was attempted on a driver that does not declare the capability")
	}
	if p.CanRevert() {
		t.Fatal("CanRevert lied about a driver with no snapshot capability")
	}
	if err := p.Revert(context.Background(), "vm-web01", "test"); err == nil {
		t.Fatal("a revert was accepted on a backend that cannot revert")
	}
}

func TestPlanDescribesWithoutTouching(t *testing.T) {
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})

	changes, err := p.Plan(context.Background(), specs())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].Action != "create" {
		t.Fatalf("plan: %+v", changes)
	}
	if len(fake.log()) != 0 {
		t.Fatalf("plan changed something: %v", fake.log())
	}
}

func TestStatusReportsWhatAnOperatorNeeds(t *testing.T) {
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if _, err := p.Reconcile(context.Background(), specs()); err != nil {
		t.Fatal(err)
	}
	if err := p.Burn(context.Background(), "vm-dc01", "ransomware detonated"); err != nil {
		t.Fatal(err)
	}

	st := p.Status()
	if len(st) != 2 {
		t.Fatalf("status reported %d decoys", len(st))
	}
	byID := map[string]VMStatus{}
	for _, s := range st {
		byID[s.ID] = s
	}
	if !byID["vm-web01"].Baseline {
		t.Fatal("a decoy with a baseline does not say so")
	}
	if !byID["vm-dc01"].Burned || byID["vm-dc01"].BurnReason != "ransomware detonated" {
		t.Fatalf("a burned decoy does not report why: %+v", byID["vm-dc01"])
	}
}

func TestUnknownDecoyIsNotSilentlyIgnored(t *testing.T) {
	fake := newFake()
	p, _ := build(t, Options{Compute: fake, ComputeInfo: snapshotCapable(),
		Fabric: &fakeFabric{}})
	if err := p.Burn(context.Background(), "nope", "x"); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("Burn on an unknown decoy returned %v", err)
	}
	if err := p.Revert(context.Background(), "nope", "x"); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("Revert on an unknown decoy returned %v", err)
	}
}
