package fleet

import (
	"strings"
	"testing"
	"time"
)

func plan() RotationPlan {
	return RotationPlan{Interval: 7 * 24 * time.Hour, Seed: "deploy-one"}
}

func TestScheduleIsDeterministic(t *testing.T) {
	// Rotation must be a pure function: the same plan and time always yield the
	// same identities, or a restart would rename decoys mid-flight.
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	ids := []string{"dcy-web01", "dcy-db01", "dcy-dc01"}
	a := Schedule(plan(), ids, now)
	b := Schedule(plan(), ids, now)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("identity %d differed between identical calls: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestDifferentDeploymentsRotateDifferently(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	ids := []string{"dcy-web01", "dcy-db01"}
	one := Schedule(RotationPlan{Interval: 168 * time.Hour, Seed: "one"}, ids, now)
	two := Schedule(RotationPlan{Interval: 168 * time.Hour, Seed: "two"}, ids, now)
	// At least the hostnames they would rotate to must differ; identical schedules
	// across deployments would be a signature.
	sameAll := len(one) == len(two) && len(one) > 0
	if sameAll {
		for i := range one {
			if one[i].Hostname != two[i].Hostname {
				sameAll = false
				break
			}
		}
		if sameAll {
			t.Fatal("two deployments produced identical rotation identities")
		}
	}
}

func TestExcludedDecoysAreNeverRotated(t *testing.T) {
	// A burned decoy kept as evidence, or one an analyst is examining, must not
	// be renamed under them.
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	p := plan()
	p.Exclude = []string{"dcy-burned"}
	got := Schedule(p, []string{"dcy-web01", "dcy-burned", "dcy-db01"}, now)
	for _, d := range got {
		if d.ID == "dcy-burned" {
			t.Fatal("an excluded decoy was scheduled for rotation")
		}
	}
}

func TestNewIdentityHasAPlausibleHostname(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	got := Schedule(plan(), []string{"dcy-web01"}, now)
	for _, d := range got {
		if d.Hostname == "" {
			t.Fatal("a rotated decoy got an empty hostname")
		}
		if d.Seed == "" {
			t.Fatal("a rotated decoy got no generation seed")
		}
	}
}

func TestDeferredRespectsActiveEngagements(t *testing.T) {
	// Rotating a decoy while an attacker is inside it is the most obvious tell
	// there is. The fleet package defers to the engagement tracker.
	active := map[string]bool{"dcy-web01": true}
	if !Deferred(active, "dcy-web01") {
		t.Fatal("rotation was not deferred for an engaged decoy")
	}
	if Deferred(active, "dcy-idle") {
		t.Fatal("rotation was deferred for a decoy with no engagement")
	}
}

func TestGenerationAdvancesWithTime(t *testing.T) {
	ids := []string{"dcy-web01"}
	p := plan()
	t1 := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(p.Interval)
	a := Schedule(p, ids, t1)
	b := Schedule(p, ids, t2)
	if len(a) > 0 && len(b) > 0 && a[0].Hostname == b[0].Hostname {
		t.Fatal("one full interval later should produce a different hostname")
	}
}

func TestEmptyDecoyListReturnsNil(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	got := Schedule(plan(), nil, now)
	if len(got) != 0 {
		t.Fatalf("nil decoy list returned %d identities, want 0", len(got))
	}
	got = Schedule(plan(), []string{}, now)
	if len(got) != 0 {
		t.Fatalf("empty decoy list returned %d identities, want 0", len(got))
	}
}

func TestAllExcludedReturnsEmpty(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	ids := []string{"dcy-a", "dcy-b", "dcy-c"}
	p := plan()
	p.Exclude = ids
	got := Schedule(p, ids, now)
	if len(got) != 0 {
		t.Fatalf("all-excluded returned %d identities, want 0", len(got))
	}
}

func TestHostnameFormat(t *testing.T) {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	ids := []string{"dcy-web01", "dcy-db01", "dcy-dc01"}
	got := Schedule(plan(), ids, now)
	for _, d := range got {
		if d.Hostname == "" {
			t.Fatal("empty hostname")
		}
		upper := strings.ToUpper(d.Hostname)
		if d.Hostname != upper {
			t.Fatalf("hostname %q is not uppercase", d.Hostname)
		}
		if !strings.Contains(d.Hostname, "-") {
			t.Fatalf("hostname %q has no dash separator", d.Hostname)
		}
	}
}
