package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/driverset"
)

// smoketestCmd exercises a compute driver's full lifecycle against a LIVE
// hypervisor, so an operator can validate a driver (Proxmox, vSphere, Hyper-V…)
// on their own estate and move it from "experimental" to field-proven. It is
// the runbook step behind docs/validation-matrix.md.
//
// It runs: Probe -> Create (adopt/clone) -> Start -> Status(running) ->
// Snapshot -> Revert -> Stop, printing PASS/FAIL for each. It does NOT destroy
// the VM unless --cleanup is given, so the operator can inspect the result.
func smoketestCmd(args []string) error {
	fs := flag.NewFlagSet("vms smoketest", flag.ExitOnError)
	cfgPath := fs.String("config", "profiles/p0-box.yaml", "configuration file (its drivers.compute is used)")
	template := fs.String("template", "", "template/source VM to clone or adopt from (required)")
	name := fs.String("name", "mirage-smoketest", "name for the decoy VM to create")
	cleanup := fs.Bool("cleanup", false, "destroy the VM at the end (default: leave it for inspection)")
	skipSnap := fs.Bool("skip-snapshot", false, "skip the snapshot/revert steps")
	settle := fs.Duration("settle", 20*time.Second, "how long to wait after Start before checking status")
	fs.Parse(args)

	if *template == "" {
		return fmt.Errorf("--template is required (a source VM/template the driver can adopt or clone)")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	name2 := cfg.Drivers.Compute
	if name2 == "" {
		name2 = "inproc"
	}
	reg := driverset.Default()
	defer reg.Close()

	info, ok := reg.Info(drivers.KindCompute, name2)
	if !ok {
		return fmt.Errorf("unknown compute driver %q", name2)
	}
	compute, err := reg.Compute(name2, cfg.Drivers.ComputeConfig)
	if err != nil {
		return fmt.Errorf("open compute driver %q: %w", name2, err)
	}
	defer compute.Close()

	fmt.Printf("smoke-testing compute driver %q", name2)
	if info.Experimental {
		fmt.Print("  [EXPERIMENTAL]")
	}
	fmt.Printf("\ntemplate=%q  decoy=%q\n\n", *template, *name)

	ctx := context.Background()
	passed, failed := 0, 0
	step := func(label string, fn func() error) bool {
		fmt.Printf("  %-28s ", label+" …")
		if err := fn(); err != nil {
			fmt.Printf("FAIL: %v\n", err)
			failed++
			return false
		}
		fmt.Println("PASS")
		passed++
		return true
	}

	step("probe", func() error { return compute.Probe(ctx) })

	spec := drivers.DecoySpec{ID: *name, Name: *name, Template: *template}
	var handle string
	if step("create (adopt/clone)", func() error {
		st, err := compute.Create(ctx, spec)
		if err != nil {
			return err
		}
		handle = st.Handle
		return nil
	}) {
		fmt.Printf("      handle=%s\n", handle)
	}

	step("start", func() error { return compute.Start(ctx, *name) })

	if *settle > 0 {
		fmt.Printf("      waiting %s to settle …\n", *settle)
		time.Sleep(*settle)
	}

	step("status is running", func() error {
		st, err := compute.Status(ctx, *name)
		if err != nil {
			return err
		}
		if st.State != drivers.StateRunning {
			return fmt.Errorf("state is %q, expected running", st.State)
		}
		return nil
	})

	hasSnapshot := false
	for _, c := range info.Capabilities {
		if c == drivers.CapSnapshot {
			hasSnapshot = true
		}
	}
	switch {
	case *skipSnap:
		// operator opted out
	case !hasSnapshot:
		fmt.Printf("  %-28s SKIP (driver declares no snapshot capability)\n", "snapshot/revert …")
	default:
		snap := "smoketest-" + time.Now().UTC().Format("150405")
		step("snapshot", func() error { return compute.Snapshot(ctx, *name, snap) })
		step("revert", func() error { return compute.Revert(ctx, *name, snap) })
	}

	step("stop", func() error { return compute.Stop(ctx, *name) })

	if *cleanup {
		step("destroy (cleanup)", func() error { return compute.Destroy(ctx, *name) })
	} else {
		fmt.Printf("\n  (left %q in place; re-run with --cleanup to destroy)\n", *name)
	}

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d smoke-test step(s) failed", failed)
	}
	if info.Experimental {
		fmt.Printf("\nAll steps passed against a live %s host. If this held for both a Linux\n"+
			"and a Windows guest, the driver is validated — report it so the\n"+
			"Experimental flag can be lifted (see docs/validation-matrix.md).\n", name2)
	}
	return nil
}
