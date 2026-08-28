package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// ProxmoxInfo describes the Proxmox VE compute driver.
func ProxmoxInfo() drivers.Info {
	return drivers.Info{
		Name: "proxmox",
		Kind: drivers.KindCompute,
		Summary: "Full-OS decoys on Proxmox VE via the pvesh CLI. Supports linked clones from " +
			"templates, snapshots and revert, and runs on the same hypervisor the user already " +
			"has — no separate KVM setup needed.",
		Capabilities: []drivers.Capability{
			drivers.CapClone, drivers.CapLinkedClone, drivers.CapSnapshot,
			drivers.CapRevert, drivers.CapFullOS,
		},
	}
}

// Proxmox drives Proxmox VE through pvesh (the Proxmox CLI). Shelling out
// rather than calling the REST API directly keeps the build without HTTP client
// dependencies and works the same way the operator's own scripts do, so error
// messages and behaviour are familiar.
type Proxmox struct {
	pvesh string
	node  string
	pool  string
	run   runner
}

// NewProxmox builds the driver. Config keys: "node" (required, the PVE node
// name), "pool" (optional, resource pool for decoy VMs), "pvesh" (binary path).
func NewProxmox(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	node := get("node", "")
	if node == "" {
		return nil, fmt.Errorf("compute/proxmox: \"node\" is required — the PVE node name " +
			"(the one `pvesh get /nodes` lists)")
	}
	return &Proxmox{
		pvesh: get("pvesh", "pvesh"),
		node:  node,
		pool:  get("pool", "mirage"),
		run:   execRunner{timeout: 5 * time.Minute},
	}, nil
}

func (p *Proxmox) Info() drivers.Info { return ProxmoxInfo() }

func (p *Proxmox) Probe(ctx context.Context) error {
	if !binaryExists(p.pvesh) {
		return fmt.Errorf("compute/proxmox: %q not found on PATH; this driver runs on a Proxmox VE node", p.pvesh)
	}
	if _, err := p.pveshGet(ctx, "/nodes/"+p.node+"/status"); err != nil {
		return fmt.Errorf("compute/proxmox: cannot reach node %q: %w", p.node, err)
	}
	return nil
}

func (p *Proxmox) Close() error { return nil }

// Create clones a VM from a template. The template must already exist on this
// node as a Proxmox template — MIRAGE clones it, it does not build it.
func (p *Proxmox) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	vmid, err := p.nextVMID(ctx)
	if err != nil {
		return drivers.DecoyStatus{}, err
	}

	args := []string{
		"create", fmt.Sprintf("/nodes/%s/qemu/%s/clone", p.node, spec.Template),
		"--newid", vmid,
		"--name", spec.Name,
		"--full", "0", // linked clone
	}
	if p.pool != "" {
		args = append(args, "--pool", p.pool)
	}
	if _, err := p.run.run(ctx, p.pvesh, args...); err != nil {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/proxmox: clone %s from template %s: %w",
			spec.ID, spec.Template, err)
	}

	if spec.CPUs > 0 {
		p.run.run(ctx, p.pvesh, "set", p.vmPath(vmid), "--cores", fmt.Sprint(spec.CPUs))
	}
	if spec.MemoryMB > 0 {
		p.run.run(ctx, p.pvesh, "set", p.vmPath(vmid), "--memory", fmt.Sprint(spec.MemoryMB))
	}

	return drivers.DecoyStatus{
		ID: spec.ID, Handle: "proxmox/" + vmid,
		State: drivers.StateCreated, CreatedAt: time.Now(),
	}, nil
}

func (p *Proxmox) Start(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	_, err = p.run.run(ctx, p.pvesh, "create", p.vmPath(vmid)+"/status/start")
	if err != nil {
		return fmt.Errorf("compute/proxmox: start %s (vmid %s): %w", id, vmid, err)
	}
	return nil
}

func (p *Proxmox) Stop(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	_, err = p.run.run(ctx, p.pvesh, "create", p.vmPath(vmid)+"/status/stop")
	if err != nil {
		return fmt.Errorf("compute/proxmox: stop %s: %w", id, err)
	}
	return nil
}

func (p *Proxmox) Destroy(ctx context.Context, id string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	_, err = p.run.run(ctx, p.pvesh, "delete", p.vmPath(vmid), "--purge", "1")
	if err != nil {
		return fmt.Errorf("compute/proxmox: destroy %s: %w", id, err)
	}
	return nil
}

func (p *Proxmox) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	out, err := p.pveshGet(ctx, p.vmPath(vmid)+"/status/current")
	if err != nil {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	var status struct {
		Status string `json:"status"`
	}
	json.Unmarshal([]byte(out), &status)
	st := drivers.StateStopped
	if status.Status == "running" {
		st = drivers.StateRunning
	}
	return drivers.DecoyStatus{ID: id, Handle: "proxmox/" + vmid, State: st}, nil
}

func (p *Proxmox) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	out, err := p.pveshGet(ctx, fmt.Sprintf("/nodes/%s/qemu", p.node))
	if err != nil {
		return nil, err
	}
	var vms []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return nil, fmt.Errorf("compute/proxmox: parse vm list: %w", err)
	}

	var result []drivers.DecoyStatus
	for _, vm := range vms {
		if p.pool != "" && !p.inPool(ctx, fmt.Sprint(vm.VMID)) {
			continue
		}
		st := drivers.StateStopped
		if vm.Status == "running" {
			st = drivers.StateRunning
		}
		result = append(result, drivers.DecoyStatus{
			ID: vm.Name, Handle: fmt.Sprintf("proxmox/%d", vm.VMID), State: st,
		})
	}
	return result, nil
}

func (p *Proxmox) Snapshot(ctx context.Context, id, name string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	_, err = p.run.run(ctx, p.pvesh, "create", p.vmPath(vmid)+"/snapshot",
		"--snapname", name, "--vmstate", "1")
	if err != nil {
		return fmt.Errorf("compute/proxmox: snapshot %s: %w", id, err)
	}
	return nil
}

func (p *Proxmox) Revert(ctx context.Context, id, name string) error {
	vmid, err := p.findVMID(ctx, id)
	if err != nil {
		return err
	}
	_, err = p.run.run(ctx, p.pvesh, "create",
		fmt.Sprintf("%s/snapshot/%s/rollback", p.vmPath(vmid), name))
	if err != nil {
		return fmt.Errorf("compute/proxmox: revert %s to %s: %w", id, name, err)
	}
	return nil
}

// --- helpers ---

func (p *Proxmox) vmPath(vmid string) string {
	return fmt.Sprintf("/nodes/%s/qemu/%s", p.node, vmid)
}

func (p *Proxmox) pveshGet(ctx context.Context, path string) (string, error) {
	return p.run.run(ctx, p.pvesh, "get", path, "--output-format", "json")
}

func (p *Proxmox) nextVMID(ctx context.Context) (string, error) {
	out, err := p.pveshGet(ctx, "/cluster/nextid")
	if err != nil {
		return "", fmt.Errorf("compute/proxmox: next vmid: %w", err)
	}
	return strings.TrimSpace(strings.Trim(out, "\"")), nil
}

// findVMID resolves a MIRAGE decoy id to a Proxmox VMID by name.
func (p *Proxmox) findVMID(ctx context.Context, name string) (string, error) {
	out, err := p.pveshGet(ctx, fmt.Sprintf("/nodes/%s/qemu", p.node))
	if err != nil {
		return "", err
	}
	var vms []struct {
		VMID int    `json:"vmid"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return "", err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return fmt.Sprint(vm.VMID), nil
		}
	}
	return "", fmt.Errorf("compute/proxmox: no VM named %q on node %s", name, p.node)
}

func (p *Proxmox) inPool(ctx context.Context, vmid string) bool {
	out, _ := p.pveshGet(ctx, "/pools/"+p.pool)
	return strings.Contains(out, vmid)
}

var _ drivers.ComputeDriver = (*Proxmox)(nil)
