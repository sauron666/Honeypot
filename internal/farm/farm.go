// Package farm provisions full-OS decoys.
//
// Everything else in MIRAGE emulates: a service that answers convincingly and
// can never be owned, because there is nothing behind it to own. A full VM is
// the opposite trade. It is indistinguishable from a real host because it is a
// real host -- and an attacker who takes it has a real host, in the customer's
// estate, with a real network stack.
//
// That single fact drives the design of this package. Nothing starts until
// containment has been asserted rather than assumed; the dirty state of an
// owned decoy is snapshotted as evidence before anything resets it; and a decoy
// that has been burned is never quietly recycled back into service.
package farm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// BaselineSnapshot is the clean state every provisioned decoy is taken back to.
const BaselineSnapshot = "mirage-baseline"

// RevertPolicy says what happens to a decoy after an attacker has been in it.
type RevertPolicy string

const (
	// RevertNever leaves the decoy exactly as the attacker left it. Correct
	// when an analyst still wants to walk the live host.
	RevertNever RevertPolicy = "never"
	// RevertOnEngagementEnd resets the decoy once the attacker has gone quiet.
	// The next visitor finds a clean host, which is what makes a decoy reusable
	// instead of single-use.
	RevertOnEngagementEnd RevertPolicy = "on_engagement_end"
)

// Spec is one full-OS decoy as declared in the manifest.
type Spec struct {
	ID       string            `yaml:"id" json:"id"`
	Persona  string            `yaml:"persona" json:"persona"`
	Template string            `yaml:"template" json:"template"`
	CPUs     int               `yaml:"cpus" json:"cpus,omitempty"`
	MemoryMB int               `yaml:"memory_mb" json:"memory_mb,omitempty"`
	Segment  string            `yaml:"segment" json:"segment,omitempty"`
	Revert   RevertPolicy      `yaml:"revert" json:"revert,omitempty"`
	Labels   map[string]string `yaml:"labels" json:"labels,omitempty"`
}

// Options configures the provisioner.
type Options struct {
	// Compute runs the decoys. Required.
	Compute drivers.ComputeDriver
	// ComputeInfo carries the driver's declared capabilities, which decide
	// whether snapshot and revert are available at all.
	ComputeInfo drivers.Info
	// Fabric enforces and, more importantly, verifies containment. A nil
	// fabric is a deployment with nothing checking that the decoy segment
	// cannot reach production.
	Fabric drivers.FabricDriver
	// ContainmentUnenforced is the operator saying, explicitly and in the
	// manifest, that they have contained the decoy segment by other means and
	// accept that MIRAGE cannot verify it. Without either a fabric driver or
	// this acknowledgement, no full-OS decoy is started -- a VM an attacker can
	// own, on a network nobody has checked, is a beachhead we would have built
	// for them.
	ContainmentUnenforced bool

	Publish func(*event.Event)
	Log     *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// Provisioner reconciles declared full-OS decoys against a compute backend.
type Provisioner struct {
	opt Options
	log *slog.Logger
	now func() time.Time

	canSnapshot bool
	canRevert   bool

	mu    sync.Mutex
	state map[string]*vmState
}

type vmState struct {
	spec     Spec
	status   drivers.DecoyStatus
	baseline bool
	burned   bool
	// burnReason survives a restart of the engagement, not of the process; it
	// is here so the API can say why a decoy is out of service.
	burnReason string
	lastRevert time.Time
}

// VMStatus is what the API reports about one full-OS decoy.
type VMStatus struct {
	ID         string       `json:"id"`
	Persona    string       `json:"persona"`
	Template   string       `json:"template"`
	Handle     string       `json:"handle,omitempty"`
	State      string       `json:"state"`
	IPs        []string     `json:"ips,omitempty"`
	Baseline   bool         `json:"baseline"`
	Burned     bool         `json:"burned"`
	BurnReason string       `json:"burn_reason,omitempty"`
	Revert     RevertPolicy `json:"revert"`
	LastRevert time.Time    `json:"last_revert,omitempty"`
}

// ErrNotProvisioned is returned for an id the provisioner does not manage.
var ErrNotProvisioned = errors.New("farm: no such full-OS decoy")

// New builds a provisioner.
func New(opt Options) (*Provisioner, error) {
	if opt.Compute == nil {
		return nil, errors.New("farm: a compute driver is required")
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Publish == nil {
		opt.Publish = func(*event.Event) {}
	}
	return &Provisioner{
		opt: opt, log: opt.Log, now: opt.Now,
		canSnapshot: opt.ComputeInfo.Has(drivers.CapSnapshot),
		canRevert:   opt.ComputeInfo.Has(drivers.CapRevert),
		state:       map[string]*vmState{},
	}, nil
}

// CanRevert reports whether the backend supports reverting to a baseline.
// Configuration validation uses it so that a revert policy the backend cannot
// honour is refused at doctor time rather than discovered after an intrusion.
func (p *Provisioner) CanRevert() bool { return p.canSnapshot && p.canRevert }

// Change is one action a reconcile would take or took.
type Change struct {
	ID     string `json:"id"`
	Action string `json:"action"` // create, start, destroy, unchanged, skip
	Reason string `json:"reason,omitempty"`
}

// Plan reports what Reconcile would do, without doing it. Bringing up a full
// VM is slow and visible; an operator deserves to see the list first.
func (p *Provisioner) Plan(ctx context.Context, specs []Spec) ([]Change, error) {
	live, err := p.observed(ctx)
	if err != nil {
		return nil, err
	}
	var out []Change
	declared := map[string]bool{}
	for _, s := range specs {
		declared[s.ID] = true
		st, known := live[s.ID]
		switch {
		case !known:
			out = append(out, Change{ID: s.ID, Action: "create",
				Reason: "declared in the manifest and not present on the backend"})
		case st.State != drivers.StateRunning:
			out = append(out, Change{ID: s.ID, Action: "start",
				Reason: fmt.Sprintf("present but %s", st.State)})
		default:
			out = append(out, Change{ID: s.ID, Action: "unchanged"})
		}
	}
	for id := range live {
		if !declared[id] && p.manages(id) {
			out = append(out, Change{ID: id, Action: "destroy",
				Reason: "no longer declared in the manifest"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Reconcile brings the backend in line with the manifest.
func (p *Provisioner) Reconcile(ctx context.Context, specs []Spec) ([]Change, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	// The gate is checked once per reconcile rather than per decoy: it is a
	// property of the deployment, and asking a fabric driver the same question
	// once per VM would be noise in its logs during a rebuild.
	if err := p.assertContainment(ctx); err != nil {
		return nil, err
	}

	live, err := p.observed(ctx)
	if err != nil {
		return nil, err
	}

	var out []Change
	declared := map[string]bool{}
	for _, spec := range specs {
		declared[spec.ID] = true

		p.mu.Lock()
		burned := p.state[spec.ID] != nil && p.state[spec.ID].burned
		reason := ""
		if burned {
			reason = p.state[spec.ID].burnReason
		}
		p.mu.Unlock()
		if burned {
			// A burned decoy is evidence. Recycling it would overwrite what an
			// attacker left behind, and would put a host they already own back
			// in front of them as if it were new.
			out = append(out, Change{ID: spec.ID, Action: "skip",
				Reason: "burned: " + reason})
			continue
		}

		st, known := live[spec.ID]
		if !known {
			st, err = p.opt.Compute.Create(ctx, drivers.DecoySpec{
				ID: spec.ID, Name: spec.ID, Persona: spec.Persona,
				Template: spec.Template, CPUs: spec.CPUs, MemoryMB: spec.MemoryMB,
				Segment: spec.Segment, Labels: spec.Labels,
			})
			if err != nil {
				return out, fmt.Errorf("farm: create %s: %w", spec.ID, err)
			}
			out = append(out, Change{ID: spec.ID, Action: "create"})
			p.emit(event.SeverityInformational, spec, "full-OS decoy created from template %s", spec.Template)
		}

		if st.State != drivers.StateRunning {
			if err := p.opt.Compute.Start(ctx, spec.ID); err != nil {
				return out, fmt.Errorf("farm: start %s: %w", spec.ID, err)
			}
			if known {
				out = append(out, Change{ID: spec.ID, Action: "start"})
			}
			st.State = drivers.StateRunning
		} else if known {
			out = append(out, Change{ID: spec.ID, Action: "unchanged"})
		}

		p.mu.Lock()
		s := p.state[spec.ID]
		if s == nil {
			s = &vmState{}
			p.state[spec.ID] = s
		}
		s.spec = spec
		s.status = st
		takeBaseline := p.canSnapshot && !s.baseline
		p.mu.Unlock()

		if takeBaseline {
			// The baseline is taken after the decoy is up, so that it captures
			// a booted host rather than a cold image: reverting to a cold image
			// would take the decoy offline for a boot every time, which an
			// attacker who is watching would notice.
			if err := p.opt.Compute.Snapshot(ctx, spec.ID, BaselineSnapshot); err != nil {
				// Not fatal: a decoy without a baseline still works, it just
				// cannot be reset. Saying so is better than refusing to run.
				p.log.Warn("farm: could not take a baseline snapshot; this decoy cannot be reset",
					"decoy", spec.ID, "err", err)
			} else {
				p.mu.Lock()
				p.state[spec.ID].baseline = true
				p.mu.Unlock()
			}
		}
	}

	for id, st := range live {
		if declared[id] || !p.manages(id) {
			continue
		}
		p.mu.Lock()
		burned := p.state[id] != nil && p.state[id].burned
		p.mu.Unlock()
		if burned {
			// Removing a burned decoy from the manifest is not authority to
			// destroy it. It is the forensic artefact of an intrusion, and a
			// reconcile is the last place that decision should be made.
			p.log.Warn("farm: a burned decoy is no longer declared, but is kept as evidence; "+
				"destroy it deliberately once it has been collected", "decoy", id)
			out = append(out, Change{ID: id, Action: "skip",
				Reason: "burned and kept as evidence despite no longer being declared"})
			continue
		}
		if err := p.opt.Compute.Destroy(ctx, id); err != nil {
			p.log.Warn("farm: could not destroy an undeclared decoy", "decoy", id, "err", err)
			continue
		}
		_ = st
		p.mu.Lock()
		delete(p.state, id)
		p.mu.Unlock()
		out = append(out, Change{ID: id, Action: "destroy"})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// assertContainment refuses to run full-OS decoys on an unverified network.
func (p *Provisioner) assertContainment(ctx context.Context) error {
	if p.opt.Fabric == nil {
		if p.opt.ContainmentUnenforced {
			p.log.Warn("full-OS decoys are starting with containment unverified; " +
				"MIRAGE cannot confirm the decoy segment is unable to reach production " +
				"(vms.containment: unenforced)")
			p.emitPlain(event.SeverityMedium,
				"full-OS decoys started with containment unverified, by explicit configuration")
			return nil
		}
		return errors.New("farm: full-OS decoys need a fabric driver to verify containment, " +
			"because a VM an attacker can own is a real host on the customer's network; " +
			"configure drivers.fabric, or set vms.containment: unenforced to accept " +
			"responsibility for containing the decoy segment yourself")
	}
	violations, err := p.opt.Fabric.AssertContainment(ctx)
	if err != nil {
		return fmt.Errorf("farm: containment could not be verified: %w", err)
	}
	if len(violations) > 0 {
		p.emitPlain(event.SeverityCritical,
			"full-OS decoys refused to start: containment is violated (%s)",
			strings.Join(violations, "; "))
		return fmt.Errorf("farm: refusing to start full-OS decoys, containment is violated: %s",
			strings.Join(violations, "; "))
	}
	return nil
}

// Burn takes a decoy out of service and preserves it.
//
// It is what happens when the evidence says an attacker owns the host: the
// decoy stops, the fabric isolates it if it can, and it is never restarted or
// reverted, because either would destroy what is now the best forensic artefact
// the deployment has.
func (p *Provisioner) Burn(ctx context.Context, id, reason string) error {
	p.mu.Lock()
	s := p.state[id]
	if s == nil {
		p.mu.Unlock()
		return ErrNotProvisioned
	}
	if s.burned {
		p.mu.Unlock()
		return nil
	}
	spec := s.spec
	p.mu.Unlock()

	// Isolate first. Stopping the VM first would give whatever is running
	// inside it a window in which the host is still on the network and the
	// operator believes it is being handled.
	if p.opt.Fabric != nil {
		if err := p.opt.Fabric.Isolate(ctx, id); err != nil {
			p.log.Error("farm: could not isolate a burned decoy; it may still be on the network",
				"decoy", id, "err", err)
		}
	}
	if err := p.opt.Compute.Stop(ctx, id); err != nil {
		p.log.Warn("farm: could not stop a burned decoy", "decoy", id, "err", err)
	}

	p.mu.Lock()
	s.burned = true
	s.burnReason = reason
	s.status.State = drivers.StateBurned
	p.mu.Unlock()

	p.emit(event.SeverityHigh, spec, "full-OS decoy burned and preserved: %s", reason)
	return nil
}

// Revert takes a decoy back to its baseline, keeping the dirty state first.
func (p *Provisioner) Revert(ctx context.Context, id, reason string) error {
	p.mu.Lock()
	s := p.state[id]
	if s == nil {
		p.mu.Unlock()
		return ErrNotProvisioned
	}
	if s.burned {
		p.mu.Unlock()
		return fmt.Errorf("farm: %s is burned and is evidence; it is not reverted", id)
	}
	if !s.baseline {
		p.mu.Unlock()
		return fmt.Errorf("farm: %s has no baseline snapshot to return to", id)
	}
	spec := s.spec
	p.mu.Unlock()

	if !p.CanRevert() {
		return fmt.Errorf("farm: the %s driver cannot revert", p.opt.ComputeInfo.Name)
	}

	// Keep the dirty state before discarding it. Whatever the attacker
	// installed is the finding; a reset that erases it turns an intrusion into
	// an anecdote.
	incident := fmt.Sprintf("mirage-incident-%s", p.now().UTC().Format("20060102T150405Z"))
	if err := p.opt.Compute.Snapshot(ctx, id, incident); err != nil {
		return fmt.Errorf("farm: refusing to revert %s: the dirty state could not be preserved: %w",
			id, err)
	}
	if err := p.opt.Compute.Revert(ctx, id, BaselineSnapshot); err != nil {
		return fmt.Errorf("farm: revert %s: %w", id, err)
	}

	p.mu.Lock()
	s.lastRevert = p.now()
	p.mu.Unlock()

	p.emit(event.SeverityMedium, spec,
		"full-OS decoy reset to baseline (%s); the attacker's state is kept as %s", reason, incident)
	return nil
}

// OnEngagementClosed resets the decoys whose policy asks for it.
//
// It is deliberately driven by the engagement ending rather than by a timer:
// resetting a host while the attacker is still in it is the single most
// obvious tell a deception platform can produce.
func (p *Provisioner) OnEngagementClosed(ctx context.Context, decoyIDs []string) {
	for _, id := range decoyIDs {
		p.mu.Lock()
		s := p.state[id]
		reset := s != nil && !s.burned && s.baseline && s.spec.Revert == RevertOnEngagementEnd
		p.mu.Unlock()
		if !reset {
			continue
		}
		if err := p.Revert(ctx, id, "the engagement ended"); err != nil {
			p.log.Warn("farm: could not reset a decoy after an engagement", "decoy", id, "err", err)
		}
	}
}

// Status reports every managed decoy.
func (p *Provisioner) Status() []VMStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]VMStatus, 0, len(p.state))
	for id, s := range p.state {
		out = append(out, VMStatus{
			ID: id, Persona: s.spec.Persona, Template: s.spec.Template,
			Handle: s.status.Handle, State: string(s.status.State), IPs: s.status.IPs,
			Baseline: s.baseline, Burned: s.burned, BurnReason: s.burnReason,
			Revert: s.spec.Revert, LastRevert: s.lastRevert,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// manages reports whether an id came from this deployment's manifest, so that
// a reconcile never destroys somebody else's VM that happens to share a host.
func (p *Provisioner) manages(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.state[id]
	return ok
}

func (p *Provisioner) observed(ctx context.Context) (map[string]drivers.DecoyStatus, error) {
	list, err := p.opt.Compute.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("farm: list decoys: %w", err)
	}
	out := make(map[string]drivers.DecoyStatus, len(list))
	for _, st := range list {
		out[st.ID] = st
	}
	return out, nil
}

func (p *Provisioner) emit(sev event.Severity, spec Spec, format string, args ...any) {
	e := event.New(event.ClassContainment, 1, sev, event.PlaneDirector).
		WithMessage(format, args...)
	e.Mirage.DecoyID = spec.ID
	e.Mirage.Persona = spec.Persona
	e.Set("template", spec.Template)
	p.opt.Publish(e)
}

func (p *Provisioner) emitPlain(sev event.Severity, format string, args ...any) {
	p.opt.Publish(event.New(event.ClassContainment, 1, sev, event.PlaneDirector).
		WithMessage(format, args...))
}
