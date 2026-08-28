package compute

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// LibvirtInfo describes the full-OS decoy driver.
func LibvirtInfo() drivers.Info {
	return drivers.Info{
		Name: "libvirt",
		Kind: drivers.KindCompute,
		Summary: "Full-OS decoys on KVM via libvirt. Supports linked clones, snapshots and " +
			"instant revert, and is the only backend where agentless VMI is available.",
		Capabilities: []drivers.Capability{
			drivers.CapClone, drivers.CapLinkedClone, drivers.CapSnapshot,
			drivers.CapRevert, drivers.CapConsole, drivers.CapFullOS,
		},
	}
}

// Libvirt drives KVM through virsh and virt-clone. Shelling out rather than
// linking libvirt-go keeps the build cgo-free, which matters for a product that
// ships as a single static binary.
type Libvirt struct {
	virsh     string
	virtClone string
	uri       string
	run       runner
}

// NewLibvirt builds the driver. Config keys: "uri" (default qemu:///system),
// "virsh", "virt_clone".
func NewLibvirt(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	return &Libvirt{
		virsh:     get("virsh", "virsh"),
		virtClone: get("virt_clone", "virt-clone"),
		uri:       get("uri", "qemu:///system"),
		run:       execRunner{timeout: 5 * time.Minute},
	}, nil
}

func (l *Libvirt) Info() drivers.Info { return LibvirtInfo() }

func (l *Libvirt) Probe(ctx context.Context) error {
	if !binaryExists(l.virsh) {
		return fmt.Errorf("compute/libvirt: %q not found on PATH", l.virsh)
	}
	if _, err := l.virshRun(ctx, "version"); err != nil {
		return fmt.Errorf("compute/libvirt: cannot reach %s: %w", l.uri, err)
	}
	return nil
}

func (l *Libvirt) Close() error { return nil }

func (l *Libvirt) virshRun(ctx context.Context, args ...string) (string, error) {
	return l.run.run(ctx, l.virsh, append([]string{"-c", l.uri}, args...)...)
}

func (l *Libvirt) domain(id string) string { return "mirage-" + id }

// Create clones a golden template into a new decoy. Linked clones keep decoy
// cost at roughly the delta, which is what makes a large fleet affordable.
func (l *Libvirt) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	if spec.Template == "" {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/libvirt: decoy %s has no template domain", spec.ID)
	}
	args := []string{
		"--connect", l.uri,
		"--original", spec.Template,
		"--name", l.domain(spec.ID),
		"--auto-clone",
		// Regenerate the MAC so a fleet does not share one address, and so the
		// OUI can be set to match the customer's real hardware later.
		"--mac", "RANDOM",
	}
	if _, err := l.run.run(ctx, l.virtClone, args...); err != nil {
		return drivers.DecoyStatus{}, err
	}
	if err := l.Start(ctx, spec.ID); err != nil {
		return drivers.DecoyStatus{}, err
	}
	return l.Status(ctx, spec.ID)
}

func (l *Libvirt) Start(ctx context.Context, id string) error {
	_, err := l.virshRun(ctx, "start", l.domain(id))
	if err != nil && strings.Contains(err.Error(), "already active") {
		return nil
	}
	return err
}

func (l *Libvirt) Stop(ctx context.Context, id string) error {
	// destroy is libvirt's "power off", not "delete". Decoys are pulled, not
	// asked politely: a compromised guest cannot be trusted to shut down.
	_, err := l.virshRun(ctx, "destroy", l.domain(id))
	if err != nil && strings.Contains(err.Error(), "not running") {
		return nil
	}
	return err
}

func (l *Libvirt) Destroy(ctx context.Context, id string) error {
	_ = l.Stop(ctx, id)
	_, err := l.virshRun(ctx, "undefine", l.domain(id), "--remove-all-storage", "--nvram")
	return err
}

var ipLine = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)/\d+`)

func (l *Libvirt) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	out, err := l.virshRun(ctx, "domstate", l.domain(id))
	if err != nil {
		if strings.Contains(err.Error(), "failed to get domain") ||
			strings.Contains(err.Error(), "Domain not found") {
			return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
		}
		return drivers.DecoyStatus{}, err
	}
	st := drivers.DecoyStatus{ID: id, Handle: l.domain(id), State: libvirtState(strings.TrimSpace(out))}

	// Addresses are best-effort: a decoy that has not DHCPed yet is normal.
	if addrs, err := l.virshRun(ctx, "domifaddr", l.domain(id)); err == nil {
		for _, m := range ipLine.FindAllStringSubmatch(addrs, -1) {
			st.IPs = append(st.IPs, m[1])
		}
	}
	return st, nil
}

func libvirtState(s string) drivers.DecoyState {
	switch {
	case strings.HasPrefix(s, "running"):
		return drivers.StateRunning
	case strings.HasPrefix(s, "shut off"), strings.HasPrefix(s, "paused"):
		return drivers.StateStopped
	case s == "":
		return drivers.StateAbsent
	default:
		return drivers.StateCreated
	}
}

func (l *Libvirt) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	out, err := l.virshRun(ctx, "list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	var res []drivers.DecoyStatus
	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		name = strings.TrimSpace(name)
		if !strings.HasPrefix(name, "mirage-") {
			continue
		}
		id := strings.TrimPrefix(name, "mirage-")
		st, err := l.Status(ctx, id)
		if err != nil {
			continue
		}
		res = append(res, st)
	}
	return res, nil
}

func (l *Libvirt) Snapshot(ctx context.Context, id, name string) error {
	_, err := l.virshRun(ctx, "snapshot-create-as", l.domain(id), name,
		"--description", "MIRAGE evidence snapshot", "--atomic")
	return err
}

// Revert restores a decoy after an engagement. This is the operation that makes
// high-interaction decoys safe to run: every engagement ends with a clean slate.
func (l *Libvirt) Revert(ctx context.Context, id, name string) error {
	_, err := l.virshRun(ctx, "snapshot-revert", l.domain(id), name, "--running")
	return err
}

var _ drivers.ComputeDriver = (*Libvirt)(nil)
