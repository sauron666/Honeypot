package driverset

import (
	"context"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/drivers"
)

func TestDefaultRegistryHasNoSingleImplementationCategories(t *testing.T) {
	// ADR-008: a category with exactly one implementation is not an
	// abstraction, it is a wrapper around a vendor. This test is the guard.
	if problems := Default().CheckCoverage(); len(problems) > 0 {
		t.Fatalf("driver coverage:\n  %s", strings.Join(problems, "\n  "))
	}
}

func TestOpenReturnsTypedDrivers(t *testing.T) {
	r := Default()
	defer r.Close()

	c, err := r.Compute("inproc", nil)
	if err != nil {
		t.Fatalf("open compute: %v", err)
	}
	if c.Info().Kind != drivers.KindCompute {
		t.Fatal("wrong kind")
	}
	s, err := r.Sink("stdout", nil)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	if !s.Info().Has(drivers.CapAlert) {
		t.Fatal("stdout sink must declare sink.alert")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	r := Default()
	defer r.Close()
	a, err := r.Compute("inproc", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Compute("inproc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("Open must return the same instance for the same driver")
	}
}

func TestUnknownDriverErrorListsAlternatives(t *testing.T) {
	r := Default()
	defer r.Close()
	_, err := r.Compute("vsphere", nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered driver")
	}
	// The error has to be actionable: an operator with a typo should see what
	// they could have typed instead.
	if !strings.Contains(err.Error(), "inproc") || !strings.Contains(err.Error(), "libvirt") {
		t.Fatalf("error should list available drivers, got: %v", err)
	}
}

func TestWrongKindIsRejected(t *testing.T) {
	r := drivers.NewRegistry()
	// Register a sink under the compute kind to simulate a mis-wired plugin.
	info := drivers.Info{Name: "bogus", Kind: drivers.KindCompute}
	r.Register(info, func(map[string]any) (drivers.Driver, error) {
		return &notCompute{info: info}, nil
	})
	if _, err := r.Compute("bogus", nil); err == nil {
		t.Fatal("a driver that does not implement ComputeDriver must be rejected")
	}
}

type notCompute struct{ info drivers.Info }

func (n *notCompute) Info() drivers.Info          { return n.info }
func (n *notCompute) Probe(context.Context) error { return nil }
func (n *notCompute) Close() error                { return nil }

func TestInprocLifecycle(t *testing.T) {
	r := Default()
	defer r.Close()
	c, err := r.Compute("inproc", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	st, err := c.Create(ctx, drivers.DecoySpec{ID: "d1", Persona: "workstation/finance"})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != drivers.StateRunning {
		t.Fatalf("state = %s, want running", st.State)
	}
	if err := c.Stop(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(ctx, "d1"); st.State != drivers.StateStopped {
		t.Fatalf("state after stop = %s", st.State)
	}
	list, err := c.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v (%v), want 1 decoy", list, err)
	}
	if err := c.Destroy(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(ctx, "d1"); st.State != drivers.StateAbsent {
		t.Fatalf("state after destroy = %s, want absent", st.State)
	}
}

func TestUnsupportedOperationsAreExplicit(t *testing.T) {
	r := Default()
	defer r.Close()
	c, _ := r.Compute("inproc", nil)
	// A driver that cannot snapshot must say so clearly rather than pretending
	// to succeed; callers gate on capabilities, this is the backstop.
	if c.Info().Has(drivers.CapSnapshot) {
		t.Fatal("inproc must not claim snapshot support")
	}
	if err := c.Snapshot(context.Background(), "d1", "s"); err == nil {
		t.Fatal("Snapshot must fail on a driver without the capability")
	}
}

func TestCapabilitiesDifferBetweenComputeDrivers(t *testing.T) {
	r := Default()
	defer r.Close()
	byName := map[string]drivers.Info{}
	for _, i := range r.AvailableOf(drivers.KindCompute) {
		byName[i.Name] = i
	}
	// The whole point of capabilities is that they are not all the same.
	if !byName["libvirt"].Has(drivers.CapRevert) {
		t.Error("libvirt should support revert")
	}
	if byName["podman"].Has(drivers.CapRevert) {
		t.Error("podman cannot revert a container in place and must not claim it")
	}
	if !byName["libvirt"].Has(drivers.CapFullOS) || byName["podman"].Has(drivers.CapFullOS) {
		t.Error("full-OS capability is libvirt-only")
	}
}
