package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// PodmanInfo describes the container-farm driver.
func PodmanInfo() drivers.Info {
	return drivers.Info{
		Name:    "podman",
		Kind:    drivers.KindCompute,
		Summary: "Container decoys (L0-L2). No introspection; scales to hundreds of services per host.",
		Capabilities: []drivers.Capability{
			drivers.CapClone,
			drivers.CapSnapshot, // via commit
		},
	}
}

// Podman runs decoys as containers. It is the low-cost half of the hybrid
// engagement model: cheap breadth, no VMI. Escalation to a full VM is handled
// above this layer.
type Podman struct {
	bin    string
	labels map[string]string
	run    runner
}

// NewPodman builds the driver. Config keys: "binary" (default "podman").
func NewPodman(cfg map[string]any) (drivers.Driver, error) {
	bin, _ := cfg["binary"].(string)
	if bin == "" {
		bin = "podman"
	}
	return &Podman{
		bin:    bin,
		labels: map[string]string{"mirage": "decoy"},
		run:    execRunner{timeout: 2 * time.Minute},
	}, nil
}

func (p *Podman) Info() drivers.Info { return PodmanInfo() }

func (p *Podman) Probe(ctx context.Context) error {
	if !binaryExists(p.bin) {
		return fmt.Errorf("compute/podman: %q not found on PATH", p.bin)
	}
	if _, err := p.run.run(ctx, p.bin, "version", "--format", "{{.Client.Version}}"); err != nil {
		return fmt.Errorf("compute/podman: probe failed: %w", err)
	}
	return nil
}

func (p *Podman) Close() error { return nil }

func (p *Podman) name(id string) string { return "mirage-" + id }

func (p *Podman) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	if spec.Template == "" {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/podman: decoy %s has no template (container image)", spec.ID)
	}
	args := []string{"run", "-d", "--name", p.name(spec.ID),
		"--label", "mirage=decoy",
		"--label", "mirage.decoy_id=" + spec.ID,
		"--label", "mirage.persona=" + spec.Persona,
		// Decoys are assumed compromised. Drop what we can without breaking the
		// illusion, and never grant the container access to the host.
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	}
	if spec.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", spec.MemoryMB))
	}
	if spec.Segment != "" {
		args = append(args, "--network", spec.Segment)
	}
	args = append(args, spec.Template)

	if _, err := p.run.run(ctx, p.bin, args...); err != nil {
		return drivers.DecoyStatus{}, err
	}
	return p.Status(ctx, spec.ID)
}

func (p *Podman) Start(ctx context.Context, id string) error {
	_, err := p.run.run(ctx, p.bin, "start", p.name(id))
	return err
}

func (p *Podman) Stop(ctx context.Context, id string) error {
	_, err := p.run.run(ctx, p.bin, "stop", p.name(id))
	return err
}

func (p *Podman) Destroy(ctx context.Context, id string) error {
	_, err := p.run.run(ctx, p.bin, "rm", "-f", p.name(id))
	return err
}

type podmanInspect struct {
	ID    string `json:"Id"`
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	NetworkSettings struct {
		IPAddress string `json:"IPAddress"`
		Networks  map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (p *Podman) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	out, err := p.run.run(ctx, p.bin, "inspect", p.name(id))
	if err != nil {
		if strings.Contains(err.Error(), "no such") {
			return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
		}
		return drivers.DecoyStatus{}, err
	}
	var arr []podmanInspect
	if err := json.Unmarshal([]byte(out), &arr); err != nil || len(arr) == 0 {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/podman: cannot parse inspect output for %s: %w", id, err)
	}
	in := arr[0]

	st := drivers.DecoyStatus{ID: id, Handle: in.ID, State: podmanState(in.State.Status)}
	if ip := in.NetworkSettings.IPAddress; ip != "" {
		st.IPs = append(st.IPs, ip)
	}
	for _, n := range in.NetworkSettings.Networks {
		if n.IPAddress != "" {
			st.IPs = append(st.IPs, n.IPAddress)
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil {
		st.CreatedAt = t
	}
	return st, nil
}

func podmanState(s string) drivers.DecoyState {
	switch strings.ToLower(s) {
	case "running":
		return drivers.StateRunning
	case "created", "configured":
		return drivers.StateCreated
	case "exited", "stopped", "paused":
		return drivers.StateStopped
	default:
		return drivers.StateAbsent
	}
}

func (p *Podman) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	out, err := p.run.run(ctx, p.bin, "ps", "-a",
		"--filter", "label=mirage=decoy",
		"--format", "{{.Labels}}|{{.ID}}|{{.State}}")
	if err != nil {
		return nil, err
	}
	var res []drivers.DecoyStatus
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}
		res = append(res, drivers.DecoyStatus{
			ID:     labelValue(parts[0], "mirage.decoy_id"),
			Handle: parts[1],
			State:  podmanState(parts[2]),
		})
	}
	return res, nil
}

// labelValue pulls one label out of podman's "k=v,k=v" label rendering.
func labelValue(labels, want string) string {
	for _, kv := range strings.Split(labels, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && k == want {
			return v
		}
	}
	return ""
}

// Snapshot commits the container to an image. Containers have no true
// snapshot/revert, which is why CapRevert is not declared.
func (p *Podman) Snapshot(ctx context.Context, id, name string) error {
	_, err := p.run.run(ctx, p.bin, "commit", p.name(id), "mirage-snap/"+id+":"+name)
	return err
}

func (p *Podman) Revert(ctx context.Context, id, name string) error {
	return fmt.Errorf("%w: containers cannot be reverted in place; recreate the decoy instead", ErrNotSupported)
}

var _ drivers.ComputeDriver = (*Podman)(nil)
