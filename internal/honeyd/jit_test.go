package honeyd

import (
	"testing"
	"time"
)

// The scan guard is the safety net that keeps a reactive spawner from turning
// an nmap sweep into a decoy on every port. These tests pin that behaviour so
// the staged JIT feature is safe to enable later.

func newGuardAt(t *testing.T, start time.Time, threshold int, window, cooldown time.Duration) (*scanGuard, *time.Time) {
	t.Helper()
	g := newScanGuard(threshold, window, cooldown)
	clk := start
	g.now = func() time.Time { return clk }
	return g, &clk
}

func TestScanGuardSuppressesAPortSweep(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g, clk := newGuardAt(t, start, 4, 10*time.Second, 5*time.Minute)

	// One source sweeps many distinct ports in a moment (nmap).
	ports := []int{22, 80, 139, 445, 1433, 3306, 6379, 5900}
	allowed := 0
	for _, p := range ports {
		if g.allow("10.0.0.9", p) {
			allowed++
		}
		*clk = clk.Add(50 * time.Millisecond)
	}
	// At most the first (threshold-1) probes could pass before the sweep is
	// recognised; everything after is suppressed. It must never be "all".
	if allowed >= len(ports) {
		t.Fatalf("a full port sweep was allowed to spawn %d decoys — the whole point is that it must not", allowed)
	}
	if allowed > 3 {
		t.Fatalf("too many spawns before the scanner was caught: %d", allowed)
	}
	// Once flagged, further probes stay suppressed even for a fresh port.
	if g.allow("10.0.0.9", 8080) {
		t.Fatal("a flagged scanner should stay suppressed")
	}
}

func TestScanGuardAllowsATargetedAttacker(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g, clk := newGuardAt(t, start, 4, 10*time.Second, 5*time.Minute)

	// A targeted attacker keeps coming back to ONE service.
	for i := 0; i < 5; i++ {
		if !g.allow("10.0.0.5", 1433) {
			t.Fatalf("probe %d to a single port must not be treated as a scan", i)
		}
		*clk = clk.Add(2 * time.Second)
	}
}

func TestScanGuardWindowLetsSlowProbesThrough(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g, clk := newGuardAt(t, start, 4, 10*time.Second, 5*time.Minute)

	// Distinct ports, but spread far enough apart that they never coexist in
	// the window — this is browsing, not a sweep.
	for _, p := range []int{22, 80, 445, 3306, 6379} {
		if !g.allow("10.0.0.7", p) {
			t.Fatalf("slow, spread-out probes should not be flagged as a scan (port %d)", p)
		}
		*clk = clk.Add(20 * time.Second) // > window
	}
}

func TestScanGuardCooldownExpires(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g, clk := newGuardAt(t, start, 3, 10*time.Second, 1*time.Minute)

	for _, p := range []int{22, 80, 445, 1433} {
		g.allow("10.0.0.3", p)
	}
	if g.allow("10.0.0.3", 6379) {
		t.Fatal("should be suppressed during cooldown")
	}
	*clk = clk.Add(2 * time.Minute) // past cooldown and window
	if !g.allow("10.0.0.3", 6379) {
		t.Fatal("after the cooldown the source should be allowed again")
	}
}

func TestScanGuardIsPerSource(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g, clk := newGuardAt(t, start, 3, 10*time.Second, 5*time.Minute)

	// One source sweeps and gets flagged.
	for _, p := range []int{22, 80, 445, 1433} {
		g.allow("10.0.0.1", p)
		*clk = clk.Add(10 * time.Millisecond)
	}
	// A different source, one targeted probe, must be unaffected.
	if !g.allow("10.0.0.2", 1433) {
		t.Fatal("one source scanning must not suppress a different source")
	}
}
