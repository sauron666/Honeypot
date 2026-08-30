package observer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// DrakvufInfo describes the agentless VMI observer.
func DrakvufInfo() drivers.Info {
	return drivers.Info{
		Name: "drakvuf",
		Kind: drivers.KindObserver,
		Summary: "Agentless observation of a full-OS decoy via DRAKVUF on Xen: process, file, " +
			"registry and injection activity reconstructed from the hypervisor, with nothing " +
			"inside the guest for the attacker to find or disable.",
		Capabilities: []drivers.Capability{
			drivers.CapTraceProcess, drivers.CapTraceFile, drivers.CapTraceRegistry,
			drivers.CapAgentless, drivers.CapMemoryDump, drivers.CapCryptoHook,
		},
		// Until the launch glue is validated on real Xen hardware, the driver
		// is honest about being experimental rather than claiming a support it
		// has not earned.
		Experimental: true,
	}
}

// Drakvuf drives the drakvuf(1) CLI, one process per attached decoy.
//
// The parsing and mapping this driver relies on (drakvuf_parse.go) is tested
// without a hypervisor; what remains hardware-only is the launch below --
// resolving a decoy to its Xen domain and profile, and spawning drakvuf against
// it. That glue is deliberately small and isolated for exactly that reason.
type Drakvuf struct {
	bin string
	// domainOf maps a MIRAGE decoy id to a Xen domain name. On real hardware
	// this comes from the compute driver (libvirt/xl); it is a field so a test
	// can inject a resolver and so the coupling to the hypervisor stays in one
	// place.
	domainOf func(decoyID string) (domain, profile string, err error)
	run      commandRunner
}

// commandRunner starts drakvuf and yields its stdout lines. It is an interface
// so the streaming loop can be exercised without a real drakvuf binary.
type commandRunner interface {
	stream(ctx context.Context, bin string, args ...string) (<-chan []byte, error)
}

// NewDrakvuf builds the driver. Config keys: "drakvuf" (binary path).
func NewDrakvuf(cfg map[string]any) (drivers.Driver, error) {
	bin := "drakvuf"
	if v, ok := cfg["drakvuf"].(string); ok && v != "" {
		bin = v
	}
	return &Drakvuf{
		bin: bin,
		run: execCommandRunner{},
		// The default resolver refuses: a real deployment wires domainOf from
		// the compute driver. Left unset, Observe fails closed rather than
		// guessing a domain name.
		domainOf: func(string) (string, string, error) {
			return "", "", errors.New("observer/drakvuf: no decoy->domain resolver configured; " +
				"this is wired from the compute driver on a hypervisor host")
		},
	}, nil
}

func (d *Drakvuf) Info() drivers.Info { return DrakvufInfo() }

// Probe reports honestly whether this host can run DRAKVUF. It is what
// `miragectl doctor` calls, so a deployment learns at check time — not during
// an incident — that the observer will not work here.
func (d *Drakvuf) Probe(ctx context.Context) error {
	if _, err := exec.LookPath(d.bin); err != nil {
		return fmt.Errorf("observer/drakvuf: %q not found on PATH; "+
			"DRAKVUF needs a Xen dom0 host (see docs/adr/ADR-010-vmi-observer.md)", d.bin)
	}
	if err := probeXen(); err != nil {
		return fmt.Errorf("observer/drakvuf: %w", err)
	}
	return nil
}

// probeXen checks that this host is a Xen dom0. DRAKVUF cannot work without it.
func probeXen() error {
	if _, err := os.Stat("/proc/xen/capabilities"); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not a Xen host (/proc/xen/capabilities absent); " +
				"DRAKVUF requires Xen with altp2m — KVM/QEMU hosts need libvmi instead")
		}
		return err
	}
	caps, err := os.ReadFile("/proc/xen/capabilities")
	if err != nil {
		return err
	}
	if !strings.Contains(string(caps), "control_d") {
		return fmt.Errorf("this host runs Xen but is not dom0 (capabilities: %s); "+
			"DRAKVUF must run in dom0", strings.TrimSpace(string(caps)))
	}
	if _, err := exec.LookPath("xl"); err != nil {
		return fmt.Errorf("xl not found on PATH; the Xen toolstack is required")
	}
	return nil
}

func (d *Drakvuf) Close() error { return nil }

// Attach and Detach are no-ops for DRAKVUF: it attaches per Observe call, for
// the lifetime of the stream, rather than holding a persistent attachment.
func (d *Drakvuf) Attach(context.Context, string) error { return nil }
func (d *Drakvuf) Detach(context.Context, string) error { return nil }

// DumpMemory saves a full memory snapshot of a VM decoy. It resolves the decoy
// to its Xen domain and shells out to vmi-dump-memory (libvmi) or, if that is
// unavailable, to xl dump-core.
func (d *Drakvuf) DumpMemory(ctx context.Context, decoyID, outPath string) error {
	domain, _, err := d.domainOf(decoyID)
	if err != nil {
		return err
	}
	dumpBin := "vmi-dump-memory"
	if _, err := exec.LookPath(dumpBin); err != nil {
		dumpBin = "xl"
	}
	var cmd *exec.Cmd
	if dumpBin == "vmi-dump-memory" {
		cmd = exec.CommandContext(ctx, dumpBin, "-n", domain, outPath)
	} else {
		cmd = exec.CommandContext(ctx, dumpBin, "dump-core", domain, outPath)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("observer/drakvuf: memory dump of %q failed: %w\n%s", domain, err, out)
	}
	return nil
}

// Observe resolves the decoy to its Xen domain, launches drakvuf against it, and
// streams parsed sightings until the context is cancelled.
func (d *Drakvuf) Observe(ctx context.Context, decoyID string) (<-chan drivers.Sighting, error) {
	domain, profile, err := d.domainOf(decoyID)
	if err != nil {
		return nil, err
	}
	args := []string{"-o", "json", "-d", domain}
	if profile != "" {
		args = append(args, "-r", profile)
	}
	lines, err := d.run.stream(ctx, d.bin, args...)
	if err != nil {
		return nil, fmt.Errorf("observer/drakvuf: launch against domain %q: %w", domain, err)
	}

	out := make(chan drivers.Sighting, 64)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case raw, ok := <-lines:
				if !ok {
					return
				}
				if s, ok := ParseDrakvufLine(decoyID, raw); ok {
					select {
					case out <- s:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out, nil
}

// SetDomainResolver wires the decoy->domain mapping. The app calls this with a
// resolver backed by the compute driver, keeping the hypervisor coupling out of
// the driver's construction.
func (d *Drakvuf) SetDomainResolver(f func(decoyID string) (domain, profile string, err error)) {
	d.domainOf = f
}

// execCommandRunner runs the real drakvuf binary. This is the one piece that
// genuinely needs a Xen host; everything it feeds is tested with a fake runner.
type execCommandRunner struct{}

func (execCommandRunner) stream(ctx context.Context, bin string, args ...string) (<-chan []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out := make(chan []byte, 64)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			select {
			case out <- line:
			case <-ctx.Done():
				cmd.Process.Kill()
				return
			}
		}
		cmd.Wait()
	}()
	return out, nil
}

var _ drivers.ObserverDriver = (*Drakvuf)(nil)
