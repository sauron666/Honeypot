package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// HyperVInfo describes the Microsoft Hyper-V compute driver.
//
// Hyper-V has no REST API; it is driven by PowerShell cmdlets (Get-VM,
// Start-VM, Checkpoint-VM…). This driver runs them through a configurable
// shell — locally on a Windows MIRAGE host, or over SSH to a Hyper-V host that
// runs OpenSSH + PowerShell 7. Like the vSphere driver it is EXPERIMENTAL:
// unit-tested against a fake runner, not yet validated on a live Hyper-V host.
func HyperVInfo() drivers.Info {
	return drivers.Info{
		Name: "hyperv",
		Kind: drivers.KindCompute,
		Summary: "Full-OS decoys on Microsoft Hyper-V via PowerShell cmdlets, run " +
			"locally or over SSH. Power control, status/list, checkpoint (snapshot) " +
			"and restore (revert). EXPERIMENTAL: unit-tested against a fake runner, " +
			"not yet validated on a live Hyper-V host.",
		Capabilities: []drivers.Capability{
			drivers.CapSnapshot, drivers.CapRevert, drivers.CapFullOS,
		},
		Experimental: true,
	}
}

// HyperV drives Hyper-V by invoking PowerShell. Every cmdlet that returns data
// is asked for JSON (ConvertTo-Json -AsArray) so the output parses
// deterministically whether it names zero, one or many VMs.
type HyperV struct {
	run   runner
	ps    string   // PowerShell binary (pwsh / powershell)
	host  string   // optional SSH host; empty means run locally
	extra []string // extra prefix args (e.g. ssh options)
}

// NewHyperV builds the driver. Config keys:
//
//	"host"       — optional "user@host"; when set, cmdlets run over SSH
//	"powershell" — PowerShell binary (default "pwsh")
//	"ssh"        — ssh binary (default "ssh"), used only when host is set
func NewHyperV(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	h := &HyperV{
		run:  execRunner{timeout: 5 * time.Minute},
		ps:   get("powershell", "pwsh"),
		host: get("host", ""),
	}
	if h.host != "" {
		h.extra = []string{get("ssh", "ssh"), h.host}
	}
	return h, nil
}

func (h *HyperV) Info() drivers.Info { return HyperVInfo() }
func (h *HyperV) Close() error       { return nil }

// invoke runs a PowerShell script and returns stdout. It builds the argv either
// as a local PowerShell call or as `ssh host pwsh -Command <script>`.
func (h *HyperV) invoke(ctx context.Context, script string) (string, error) {
	psArgs := []string{h.ps, "-NoProfile", "-NonInteractive", "-Command", script}
	if len(h.extra) > 0 {
		name := h.extra[0]
		args := append(append([]string{}, h.extra[1:]...), psArgs...)
		return h.run.run(ctx, name, args...)
	}
	return h.run.run(ctx, psArgs[0], psArgs[1:]...)
}

func (h *HyperV) Probe(ctx context.Context) error {
	if _, err := h.invoke(ctx, "Get-VM | Out-Null"); err != nil {
		return fmt.Errorf("compute/hyperv: cannot run Get-VM (need PowerShell + Hyper-V module%s): %w",
			hostSuffix(h.host), err)
	}
	return nil
}

func hostSuffix(host string) string {
	if host == "" {
		return " on this host"
	}
	return " on " + host
}

type hvVM struct {
	Name  string `json:"Name"`
	State string `json:"State"`
}

// stateFromHyperV maps Hyper-V's VM state to ours. Hyper-V reports Running/Off/
// Saved/Paused; anything not clearly running is treated as stopped.
func stateFromHyperV(s string) drivers.DecoyState {
	if strings.EqualFold(s, "Running") {
		return drivers.StateRunning
	}
	return drivers.StateStopped
}

func (h *HyperV) list(ctx context.Context, name string) ([]hvVM, error) {
	sel := "Get-VM"
	if name != "" {
		sel = "Get-VM -Name " + psQuote(name) + " -ErrorAction SilentlyContinue"
	}
	out, err := h.invoke(ctx, sel+" | Select-Object Name,State | ConvertTo-Json -AsArray")
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	var vms []hvVM
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return nil, fmt.Errorf("compute/hyperv: parse Get-VM output: %w", err)
	}
	return vms, nil
}

func (h *HyperV) Create(ctx context.Context, spec drivers.DecoySpec) (drivers.DecoyStatus, error) {
	// Adopt an existing VM of this name if present (the common workflow:
	// pre-create the decoy, let MIRAGE manage its lifecycle).
	if vms, err := h.list(ctx, spec.Name); err != nil {
		return drivers.DecoyStatus{}, err
	} else if len(vms) > 0 {
		return drivers.DecoyStatus{
			ID: spec.ID, Handle: "hyperv/" + vms[0].Name,
			State: stateFromHyperV(vms[0].State), CreatedAt: time.Now(),
		}, nil
	}

	if spec.Template == "" {
		return drivers.DecoyStatus{}, fmt.Errorf(
			"compute/hyperv: VM %q not found and no template VHDX given to clone from", spec.Name)
	}
	// Create from a template VHDX using a differencing disk, so the golden image
	// is never written to. Generation 2 is the modern default.
	mem := spec.MemoryMB
	if mem <= 0 {
		mem = 2048
	}
	script := fmt.Sprintf(
		"$diff = Join-Path (Split-Path %s) (%s + '.avhdx'); "+
			"New-VHD -Path $diff -ParentPath %s -Differencing | Out-Null; "+
			"New-VM -Name %s -MemoryStartupBytes %dMB -VHDPath $diff -Generation 2 | Out-Null; "+
			"Write-Output 'created'",
		psQuote(spec.Template), psQuote(spec.Name), psQuote(spec.Template),
		psQuote(spec.Name), mem)
	if _, err := h.invoke(ctx, script); err != nil {
		return drivers.DecoyStatus{}, fmt.Errorf("compute/hyperv: create %q from template %q: %w",
			spec.Name, spec.Template, err)
	}
	return drivers.DecoyStatus{
		ID: spec.ID, Handle: "hyperv/" + spec.Name,
		State: drivers.StateCreated, CreatedAt: time.Now(),
	}, nil
}

func (h *HyperV) Start(ctx context.Context, id string) error {
	_, err := h.invoke(ctx, "Start-VM -Name "+psQuote(id))
	return err
}

func (h *HyperV) Stop(ctx context.Context, id string) error {
	_, err := h.invoke(ctx, "Stop-VM -Name "+psQuote(id)+" -Force")
	return err
}

func (h *HyperV) Destroy(ctx context.Context, id string) error {
	_, err := h.invoke(ctx, "Remove-VM -Name "+psQuote(id)+" -Force")
	return err
}

func (h *HyperV) Status(ctx context.Context, id string) (drivers.DecoyStatus, error) {
	vms, err := h.list(ctx, id)
	if err != nil || len(vms) == 0 {
		return drivers.DecoyStatus{ID: id, State: drivers.StateAbsent}, nil
	}
	return drivers.DecoyStatus{
		ID: id, Handle: "hyperv/" + vms[0].Name, State: stateFromHyperV(vms[0].State),
	}, nil
}

func (h *HyperV) List(ctx context.Context) ([]drivers.DecoyStatus, error) {
	vms, err := h.list(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]drivers.DecoyStatus, 0, len(vms))
	for _, vm := range vms {
		out = append(out, drivers.DecoyStatus{
			ID: vm.Name, Handle: "hyperv/" + vm.Name, State: stateFromHyperV(vm.State),
		})
	}
	return out, nil
}

func (h *HyperV) Snapshot(ctx context.Context, id, name string) error {
	_, err := h.invoke(ctx, "Checkpoint-VM -Name "+psQuote(id)+" -SnapshotName "+psQuote(name))
	return err
}

func (h *HyperV) Revert(ctx context.Context, id, name string) error {
	_, err := h.invoke(ctx, "Restore-VMCheckpoint -VMName "+psQuote(id)+
		" -Name "+psQuote(name)+" -Confirm:$false")
	return err
}

var _ drivers.ComputeDriver = (*HyperV)(nil)

// psQuote wraps a value in single quotes for PowerShell, doubling any embedded
// single quote. Decoy names and template paths come from the manifest, but
// quoting them anyway keeps a stray character from breaking the cmdlet.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
