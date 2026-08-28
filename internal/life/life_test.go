package life

import (
	"strings"
	"testing"
	"time"
)

func testEngine() *Engine {
	return New(Options{
		Seed: "deployment-one", Host: "app01", Domain: "corp.local",
		Subnet: "10.20.30",
		Actors: []Actor{
			{User: "jsmith", Home: "/home/jsmith"},
			{User: "mjones", Home: "/home/mjones"},
			{User: "backup", Service: true},
		},
	})
}

// a fixed "now" on a weekday afternoon, so the schedule is populated.
func afternoon() time.Time {
	return time.Date(2026, 3, 18, 15, 30, 0, 0, time.UTC) // a Wednesday
}

func TestHistoryIsStableAcrossReadsButAdvancesWithTime(t *testing.T) {
	// The property that matters: an attacker who runs `last` twice sees the
	// same past both times. A schedule that reshuffled on every read would be
	// a louder tell than no history at all.
	e := testEngine()
	now := afternoon()

	a := e.Logins(now)
	b := e.Logins(now)
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("two reads at the same instant disagreed: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("login %d differed between identical reads", i)
		}
	}

	// A little later, the same events are still there, plus possibly more --
	// never fewer, and never a different past.
	later := e.Logins(now.Add(2 * time.Hour))
	if len(later) < len(a) {
		t.Fatalf("history shrank as time advanced: %d then %d", len(a), len(later))
	}
	// Every earlier ended session must still be present unchanged.
	type key struct {
		user  string
		start time.Time
	}
	earlier := map[key]Login{}
	for _, l := range a {
		if !l.StillLoggedIn() {
			earlier[key{l.User, l.Start}] = l
		}
	}
	for _, l := range later {
		if prev, ok := earlier[key{l.User, l.Start}]; ok && prev.End != l.End {
			t.Fatalf("a completed %s session changed under us: %v -> %v", l.User, prev.End, l.End)
		}
	}
}

func TestDifferentDeploymentsLiveDifferentLives(t *testing.T) {
	// If two installations produced the same login history, that history would
	// be a signature identifying MIRAGE.
	one := New(Options{Seed: "one", Host: "app01", Subnet: "10.20.30",
		Actors: []Actor{{User: "jsmith"}}})
	two := New(Options{Seed: "two", Host: "app01", Subnet: "10.20.30",
		Actors: []Actor{{User: "jsmith"}}})

	now := afternoon()
	a := one.Last(now, 20)
	b := two.Last(now, 20)
	if a == b {
		t.Fatal("two deployments produced identical login history")
	}
}

func TestSomeoneIsUsuallyLoggedInDuringTheWorkday(t *testing.T) {
	// The single most valuable signal of a live host: `w` shows a session that
	// is not the attacker's. Across a run of weekday afternoons at least some
	// should have an interactive user still on.
	e := testEngine()
	found := 0
	for d := 0; d < 10; d++ {
		day := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC).AddDate(0, 0, d)
		if day.Weekday() == time.Saturday || day.Weekday() == time.Sunday {
			continue
		}
		for _, l := range e.ActiveNow(day) {
			if !l.Service {
				found++
				break
			}
		}
	}
	if found == 0 {
		t.Fatal("no interactive user was ever logged in on any weekday afternoon")
	}
}

func TestLastLogonAdvances(t *testing.T) {
	// What an LDAP lastLogonTimestamp reads. It must move forward over days, or
	// an attacker who checks it, waits, and checks again learns the account is
	// frozen.
	e := testEngine()
	t1 := e.LastLogon("jsmith", time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC))
	t2 := e.LastLogon("jsmith", time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC))
	if t1.IsZero() || t2.IsZero() {
		t.Fatalf("jsmith has no recent logon: %v / %v", t1, t2)
	}
	if !t2.After(t1) {
		t.Fatalf("lastLogon did not advance over two weeks: %v then %v", t1, t2)
	}
}

func TestAuthLogCorroboratesLast(t *testing.T) {
	// The corroboration an attacker uses: a session in `last` must have a
	// matching "Accepted password" line in auth.log at the same time. If they
	// disagree, the inconsistency is the tell.
	e := testEngine()
	now := afternoon()

	log := e.AuthLog(now, 48)
	if log == "" {
		t.Fatal("auth.log is empty on a busy host")
	}
	var recent *Login
	for _, l := range e.Logins(now) {
		if !l.Service && l.Start.After(now.Add(-48*time.Hour)) {
			ll := l
			recent = &ll
			break
		}
	}
	if recent == nil {
		t.Skip("no interactive login in the last 48h for this seed")
	}
	stamp := recent.Start.Format("15:04:05")
	if !strings.Contains(log, "Accepted password for "+recent.User) {
		t.Fatalf("auth.log has no accepted login for %s that `last` shows", recent.User)
	}
	if !strings.Contains(log, stamp) {
		t.Fatalf("auth.log and `last` disagree on when %s logged in (%s)", recent.User, stamp)
	}
}

func TestAuthLogHasBackgroundBruteForceNoise(t *testing.T) {
	// A public-facing host with zero failed logins in two days is behind a
	// firewall so tight the attacker would wonder how they got in.
	e := testEngine()
	log := e.AuthLog(afternoon(), 48)
	if !strings.Contains(log, "Failed password for invalid user") {
		t.Fatal("no background brute-force noise; the host looks unreachably firewalled")
	}
}

func TestServiceAndInteractiveLoginsLookDifferent(t *testing.T) {
	e := testEngine()
	now := afternoon()
	var svc, inter int
	for _, l := range e.Logins(now) {
		if l.Service {
			svc++
		} else {
			inter++
		}
	}
	if svc == 0 || inter == 0 {
		t.Fatalf("expected both service and interactive logins, got svc=%d inter=%d", svc, inter)
	}
	// Service accounts log in far more often than people do.
	if svc <= inter {
		t.Fatalf("service logins (%d) should outnumber interactive ones (%d)", svc, inter)
	}
}

func TestEngineNeedsNoActorsToWork(t *testing.T) {
	// A decoy that declared no users must still look inhabited, because a host
	// with a genuinely empty login history is itself unusual.
	e := New(Options{Seed: "x", Host: "h"})
	if len(e.Logins(afternoon())) == 0 {
		t.Fatal("a decoy with no declared actors produced no life at all")
	}
}

func TestNoSessionEndsInTheFuture(t *testing.T) {
	e := testEngine()
	now := afternoon()
	for _, l := range e.Logins(now) {
		if l.Start.After(now) {
			t.Fatalf("a login is scheduled in the future: %v", l.Start)
		}
		if !l.End.IsZero() && l.End.After(now) {
			t.Fatalf("a session ends in the future: %v", l.End)
		}
	}
}
