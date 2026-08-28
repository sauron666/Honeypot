// Package drivers defines the eight abstractions through which MIRAGE touches
// the outside world. Nothing in the core imports a vendor package directly:
// Proxmox, OPNsense, FreeRADIUS, Velociraptor and the rest are drivers, not
// architecture. See docs/10-INTEGRATIONS.md and ADR-008.
package drivers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind is a driver category.
type Kind string

const (
	KindCompute   Kind = "compute"   // where decoys run
	KindFabric    Kind = "fabric"    // segmentation, mirroring, isolation
	KindNAC       Kind = "nac"       // steering unknown devices into deception
	KindIdentity  Kind = "identity"  // AD/ADCS/Entra/Okta honey principals
	KindObserver  Kind = "observer"  // deep, agentless decoy observation
	KindForensics Kind = "forensics" // endpoint collection and hunting
	KindSink      Kind = "sink"      // SIEM/SOAR/chat delivery
	KindIntel     Kind = "intel"     // threat intel platforms
)

// AllKinds lists every category, for validation and UI.
func AllKinds() []Kind {
	return []Kind{KindCompute, KindFabric, KindNAC, KindIdentity,
		KindObserver, KindForensics, KindSink, KindIntel}
}

// Capability is a named ability a driver may or may not have. The planner and
// the UI consult these rather than switching on driver names, so an environment
// that cannot snapshot simply loses the snapshot button instead of failing at
// the worst possible moment.
type Capability string

const (
	// Compute
	CapClone       Capability = "compute.clone"
	CapSnapshot    Capability = "compute.snapshot"
	CapRevert      Capability = "compute.revert"
	CapConsole     Capability = "compute.console"
	CapLinkedClone Capability = "compute.linked_clone"
	CapFullOS      Capability = "compute.full_os" // L3/L4 decoys, not just containers

	// Fabric
	CapSegments   Capability = "fabric.segments"
	CapACL        Capability = "fabric.acl"
	CapMirror     Capability = "fabric.mirror"
	CapIsolate    Capability = "fabric.isolate"
	CapKillSwitch Capability = "fabric.kill_switch"

	// Observer
	CapTraceProcess  Capability = "observer.process"
	CapTraceFile     Capability = "observer.file"
	CapTraceRegistry Capability = "observer.registry"
	CapMemoryDump    Capability = "observer.memory_dump"
	CapCryptoHook    Capability = "observer.crypto_hook" // ransomware key capture
	CapAgentless     Capability = "observer.agentless"

	// Identity
	CapHoneyPrincipal Capability = "identity.honey_principal"
	CapIssueCert      Capability = "identity.issue_cert"
	CapReadSchema     Capability = "identity.read_schema"
	CapWatchAuth      Capability = "identity.watch_auth"

	// Sink
	CapAlert Capability = "sink.alert"
	CapBulk  Capability = "sink.bulk"
)

// Info describes a registered driver.
type Info struct {
	Name         string       `json:"name"`
	Kind         Kind         `json:"kind"`
	Summary      string       `json:"summary"`
	Capabilities []Capability `json:"capabilities"`
	// Experimental drivers are usable but excluded from "supported" claims.
	Experimental bool `json:"experimental"`
}

// Has reports whether the driver declares a capability.
func (i Info) Has(c Capability) bool {
	for _, have := range i.Capabilities {
		if have == c {
			return true
		}
	}
	return false
}

// Driver is what every driver implements, whatever its kind.
type Driver interface {
	Info() Info
	// Probe checks that the driver can actually reach its backend. It is run at
	// startup and by `miragectl doctor`; a driver that cannot probe is a driver
	// that will fail during an incident.
	Probe(ctx context.Context) error
	Close() error
}

// ---------------------------------------------------------------------------
// Compute
// ---------------------------------------------------------------------------

// DecoySpec describes a decoy to create.
type DecoySpec struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Persona  string            `json:"persona"`
	Template string            `json:"template"`
	CPUs     int               `json:"cpus,omitempty"`
	MemoryMB int               `json:"memory_mb,omitempty"`
	Segment  string            `json:"segment,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// DecoyState is the lifecycle state of a decoy instance.
type DecoyState string

const (
	StateAbsent   DecoyState = "absent"
	StateCreated  DecoyState = "created"
	StateRunning  DecoyState = "running"
	StateStopped  DecoyState = "stopped"
	StateIsolated DecoyState = "isolated"
	StateBurned   DecoyState = "burned"
)

// DecoyStatus is the observed state of one decoy.
type DecoyStatus struct {
	ID        string     `json:"id"`
	Handle    string     `json:"handle"` // driver-native identifier
	State     DecoyState `json:"state"`
	IPs       []string   `json:"ips,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Snapshot  string     `json:"snapshot,omitempty"`
}

// ComputeDriver runs decoys. Implementations: libvirt/KVM, Proxmox, Podman,
// vSphere, cloud. See docs/10-INTEGRATIONS.md for the support matrix.
type ComputeDriver interface {
	Driver
	Create(ctx context.Context, spec DecoySpec) (DecoyStatus, error)
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Destroy(ctx context.Context, id string) error
	Status(ctx context.Context, id string) (DecoyStatus, error)
	List(ctx context.Context) ([]DecoyStatus, error)
	// Snapshot and Revert are optional; guard with CapSnapshot/CapRevert.
	Snapshot(ctx context.Context, id, name string) error
	Revert(ctx context.Context, id, name string) error
}

// ---------------------------------------------------------------------------
// Fabric
// ---------------------------------------------------------------------------

// Zone is a logical network zone. Concrete drivers map zones onto VLANs,
// security groups, namespaces or NetworkPolicies; the core never names a VLAN.
type Zone string

const (
	ZoneProd  Zone = "prod"
	ZoneMgmt  Zone = "mgmt"
	ZoneDirty Zone = "dirty" // where decoys live
	ZoneXfer  Zone = "xfer"
)

// FabricDriver enforces segmentation and containment.
type FabricDriver interface {
	Driver
	EnsureZones(ctx context.Context, zones []Zone) error
	// AssertContainment verifies the deny rules that docs/04 requires, rather
	// than trusting that somebody configured them. It returns the violations.
	AssertContainment(ctx context.Context) ([]string, error)
	Isolate(ctx context.Context, decoyID string) error
	KillSwitch(ctx context.Context, reason string) error
}

// ---------------------------------------------------------------------------
// Observer
// ---------------------------------------------------------------------------

// Sighting is one thing observed happening inside a decoy.
//
// It is the normalised form every observer produces, whatever its depth: an
// agentless VMI driver reconstructs it from hypervisor traps, a future in-guest
// agent would report it directly, and the rest of MIRAGE does not care which.
// The fields are the union of what the deception layer needs to attribute and
// score an event; a driver fills what it can see and leaves the rest zero.
type Sighting struct {
	// DecoyID is which decoy this happened in.
	DecoyID string `json:"decoy_id"`
	// Time is when, as the observer saw it.
	Time time.Time `json:"time"`
	// Kind is the normalised category: "process", "file", "registry",
	// "injection", "crypto", "module", "net". The rest of the fields are read
	// according to it.
	Kind string `json:"kind"`
	// Action is the verb: "exec", "write", "delete", "create", "load", etc.
	Action string `json:"action"`
	// Process is the acting process image, e.g. "powershell.exe".
	Process string `json:"process,omitempty"`
	// PID and PPID locate it in the process tree.
	PID  int `json:"pid,omitempty"`
	PPID int `json:"ppid,omitempty"`
	// Target is what was acted on: a file path, a registry key, a target PID
	// for an injection.
	Target string `json:"target,omitempty"`
	// CommandLine is the full command line where the observer recovered it,
	// which is the single most useful field for understanding intent.
	CommandLine string `json:"command_line,omitempty"`
	// User is the security context the action ran as.
	User string `json:"user,omitempty"`
	// Detail carries driver-specific extras (a registry value, a crypto key,
	// the injected bytes' length) without widening this struct per driver.
	Detail map[string]string `json:"detail,omitempty"`
}

// ObserverDriver watches inside a decoy. Depth varies wildly between drivers,
// which is exactly why capabilities are declared.
//
// The point of an observer is to see what an emulated service never can: what
// the attacker actually ran once they were inside a full-OS decoy. Agentless
// (VMI) drivers do it from the hypervisor, so there is nothing inside the guest
// for the attacker to find or disable -- which is the whole reason a full-OS
// decoy is worth its cost.
type ObserverDriver interface {
	Driver
	Attach(ctx context.Context, decoyID string) error
	Detach(ctx context.Context, decoyID string) error
	DumpMemory(ctx context.Context, decoyID, outPath string) error
	// Observe streams sightings from inside a decoy until the context is
	// cancelled or the decoy stops. The channel is closed when the stream ends.
	// A driver that cannot stream (declares neither CapTraceProcess nor a file
	// trace capability) may return ErrObserveUnsupported.
	Observe(ctx context.Context, decoyID string) (<-chan Sighting, error)
}

// ErrObserveUnsupported is returned by observers that cannot stream sightings.
var ErrObserveUnsupported = errors.New("drivers: this observer cannot stream sightings")

// ErrNoOp is returned by a "none" driver whose whole purpose is to do nothing,
// so a caller can tell "nothing happened, and that is expected here" apart from
// a real failure.
var ErrNoOp = errors.New("drivers: this driver performs no action")

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

// Alert is a high-signal notification. Sinks receive alerts, not raw telemetry:
// flooding a customer's SIEM with syscall traces is how deception products get
// switched off.
type Alert struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	SrcIP        string    `json:"src_ip,omitempty"`
	DecoyID      string    `json:"decoy_id,omitempty"`
	Service      string    `json:"service,omitempty"`
	EngagementID string    `json:"engagement_id,omitempty"`
	Techniques   []string  `json:"techniques,omitempty"`
	// URL points back at the engagement in the MIRAGE UI so the analyst never
	// has to go looking for the context.
	URL    string         `json:"url,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// SinkDriver delivers alerts outward.
type SinkDriver interface {
	Driver
	Send(ctx context.Context, a Alert) error
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

var (
	ErrUnknownDriver = errors.New("drivers: unknown driver")
	ErrWrongKind     = errors.New("drivers: driver is of a different kind")
)

// Factory builds a driver from its configuration map.
type Factory func(cfg map[string]any) (Driver, error)

type registration struct {
	info    Info
	factory Factory
}

// Registry holds driver factories and the instances built from them.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]registration
	instances map[string]Driver
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: map[string]registration{},
		instances: map[string]Driver{},
	}
}

func key(kind Kind, name string) string { return string(kind) + ":" + name }

// Register adds a driver factory. Registering the same key twice is a
// programming error and panics at startup rather than shadowing silently.
func (r *Registry) Register(info Info, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(info.Kind, info.Name)
	if _, dup := r.factories[k]; dup {
		panic(fmt.Sprintf("drivers: %s registered twice", k))
	}
	r.factories[k] = registration{info: info, factory: f}
}

// Available lists registered drivers, sorted by kind then name.
func (r *Registry) Available() []Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Info, 0, len(r.factories))
	for _, reg := range r.factories {
		out = append(out, reg.info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// AvailableOf lists registered drivers of one kind.
func (r *Registry) AvailableOf(kind Kind) []Info {
	var out []Info
	for _, i := range r.Available() {
		if i.Kind == kind {
			out = append(out, i)
		}
	}
	return out
}

// Open builds (or returns the already-built) instance of a driver.
func (r *Registry) Open(kind Kind, name string, cfg map[string]any) (Driver, error) {
	k := key(kind, name)

	r.mu.RLock()
	if d, ok := r.instances[k]; ok {
		r.mu.RUnlock()
		return d, nil
	}
	reg, ok := r.factories[k]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s (have: %s)", ErrUnknownDriver, k, r.namesOf(kind))
	}

	d, err := reg.factory(cfg)
	if err != nil {
		return nil, fmt.Errorf("drivers: open %s: %w", k, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.instances[k]; ok {
		// Lost a race; keep the first instance and discard ours.
		_ = d.Close()
		return existing, nil
	}
	r.instances[k] = d
	return d, nil
}

func (r *Registry) namesOf(kind Kind) string {
	var names []string
	for _, i := range r.AvailableOf(kind) {
		names = append(names, i.Name)
	}
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, ", ")
}

// Compute opens a compute driver with the right static type.
func (r *Registry) Compute(name string, cfg map[string]any) (ComputeDriver, error) {
	d, err := r.Open(KindCompute, name, cfg)
	if err != nil {
		return nil, err
	}
	c, ok := d.(ComputeDriver)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a ComputeDriver", ErrWrongKind, name)
	}
	return c, nil
}

// Info returns the declared metadata for one registered driver. Callers need
// it to decide what a driver can do before opening it -- capabilities are the
// contract, not the driver's name (ADR-008).
func (r *Registry) Info(kind Kind, name string) (Info, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.factories[key(kind, name)]
	if !ok {
		return Info{}, false
	}
	return reg.info, true
}

// Fabric opens a fabric driver with the right static type.
func (r *Registry) Fabric(name string, cfg map[string]any) (FabricDriver, error) {
	d, err := r.Open(KindFabric, name, cfg)
	if err != nil {
		return nil, err
	}
	f, ok := d.(FabricDriver)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a FabricDriver", ErrWrongKind, name)
	}
	return f, nil
}

// Observer opens an observer driver with the right static type.
func (r *Registry) Observer(name string, cfg map[string]any) (ObserverDriver, error) {
	d, err := r.Open(KindObserver, name, cfg)
	if err != nil {
		return nil, err
	}
	o, ok := d.(ObserverDriver)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an ObserverDriver", ErrWrongKind, name)
	}
	return o, nil
}

// Sink opens a sink driver with the right static type.
func (r *Registry) Sink(name string, cfg map[string]any) (SinkDriver, error) {
	d, err := r.Open(KindSink, name, cfg)
	if err != nil {
		return nil, err
	}
	s, ok := d.(SinkDriver)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a SinkDriver", ErrWrongKind, name)
	}
	return s, nil
}

// ProbeAll probes every open instance and returns the failures by driver key.
func (r *Registry) ProbeAll(ctx context.Context) map[string]error {
	r.mu.RLock()
	snapshot := make(map[string]Driver, len(r.instances))
	for k, d := range r.instances {
		snapshot[k] = d
	}
	r.mu.RUnlock()

	failures := map[string]error{}
	for k, d := range snapshot {
		if err := d.Probe(ctx); err != nil {
			failures[k] = err
		}
	}
	return failures
}

// Close closes every open instance.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for k, d := range r.instances {
		if err := d.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("drivers: close %s: %w", k, err)
		}
		delete(r.instances, k)
	}
	return firstErr
}

// CheckCoverage enforces the rule from ADR-008: every category that is used at
// all must have at least two implementations, so the abstraction stays honest.
// It is called by tests and by `miragectl doctor`.
func (r *Registry) CheckCoverage() []string {
	var problems []string
	for _, kind := range AllKinds() {
		n := len(r.AvailableOf(kind))
		if n == 1 {
			problems = append(problems,
				fmt.Sprintf("category %q has a single implementation (%s): "+
					"an abstraction with one implementation is not an abstraction",
					kind, r.namesOf(kind)))
		}
	}
	return problems
}
