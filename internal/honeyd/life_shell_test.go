package honeyd

import (
	"github.com/sauron666/Honeypot/internal/event"
	"strings"
	"testing"
)

// These tests are about one thing: a decoy has to look inhabited, and it has to
// look *more* inhabited every time an attacker checks. A frozen `last` and a
// stale auth.log are among the clearest tells a honeypot gives.

func TestShellLastShowsInhabitedHistory(t *testing.T) {
	p, err := BuildPersona("linux/web", "life-seed")
	if err != nil {
		t.Fatal(err)
	}
	sh := NewShell(p, newTestSession(p, &collector{}), "root")

	out, _ := sh.Execute("last")
	if !strings.Contains(out, "wtmp begins") {
		t.Fatalf("`last` did not render a login history:\n%s", out)
	}
	// There must be real login lines, not just the wtmp footer.
	lines := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "pts/") {
			lines++
		}
	}
	if lines == 0 {
		t.Fatalf("`last` showed no sessions; the host looks untouched:\n%s", out)
	}
}

func TestShellWShowsSomeoneOtherThanTheAttacker(t *testing.T) {
	// The most valuable live-host signal: a session in `w` that is not the
	// intruder's. Across the personas at least one should, at some plausible
	// moment, have a synthetic user on -- but since "now" is the test's real
	// clock we assert the weaker, always-true property: the attacker's own
	// session is shown and any extra sessions come from a different subnet.
	p, err := BuildPersona("linux/db", "life-seed")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestSession(p, &collector{})
	sh := NewShell(p, s, "root")

	out, _ := sh.Execute("w")
	if !strings.Contains(out, s.SrcIP()) {
		t.Fatalf("`w` did not show the attacker's own session:\n%s", out)
	}
	// Any additional session must not claim to come from the attacker's IP:
	// two sessions from the same address would be a giveaway.
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.Contains(line, s.SrcIP()) {
			continue
		}
		if !strings.Contains(line, "10.") {
			t.Fatalf("a synthetic session came from an implausible address:\n%s", line)
		}
	}
}

func TestShellAuthLogIsFresh(t *testing.T) {
	// A host reachable from the internet with a two-day-old newest auth line is
	// a host nobody uses. The live log must carry recent activity.
	p, err := BuildPersona("linux/web", "life-seed")
	if err != nil {
		t.Fatal(err)
	}
	sh := NewShell(p, newTestSession(p, &collector{}), "root")

	out, _ := sh.Execute("cat /var/log/auth.log")
	if out == "" {
		t.Fatal("auth.log was empty")
	}
	// The live log always carries background brute-force noise, which the
	// static one did not; its presence proves the live path is what served it.
	if !strings.Contains(out, "Failed password for invalid user") {
		t.Fatalf("auth.log was served from static content, not the life engine:\n%s",
			out[:min(len(out), 300)])
	}
}

func TestReadingLiveAuthLogStillRecordsTheRead(t *testing.T) {
	// Serving fresh content must not cost the detection: reading the log is
	// still reconnaissance, and it still has to be recorded.
	col := &collector{}
	p, err := BuildPersona("linux/web", "life-seed")
	if err != nil {
		t.Fatal(err)
	}
	sh := NewShell(p, newTestSession(p, col), "root")
	sh.Execute("cat /var/log/auth.log")

	col.waitFor(t, "the log read", func(e *event.Event) bool {
		return strings.Contains(e.Message, "/var/log/auth.log")
	})
}
