package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
)

const minimal = `
tenant: acme
site: dc1
honeyd:
  decoys:
    - id: dcy-web01
      persona: linux/web
      services:
        - {service: ssh, port: 2222}
`

func TestParseAppliesSaneDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The management API must default to loopback: binding the control plane to
	// a routable address by accident is the worst mistake this file can make.
	if !strings.HasPrefix(c.API.Listen, "127.0.0.1:") {
		t.Errorf("api.listen defaults to %q, want loopback", c.API.Listen)
	}
	if c.Alerts.MinSeverity != "high" {
		t.Errorf("min_severity defaults to %q", c.Alerts.MinSeverity)
	}
	if len(c.Alerts.Sinks) != 1 || c.Alerts.Sinks[0].Driver != "stdout" {
		t.Errorf("sinks default = %+v", c.Alerts.Sinks)
	}
	if c.Storage.SyncEvery != 1 {
		t.Errorf("evidence must be synced by default, got sync_every=%d", c.Storage.SyncEvery)
	}
	if c.Drivers.Compute != "inproc" {
		t.Errorf("compute driver default = %q", c.Drivers.Compute)
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	// A silently ignored typo in a deception configuration means decoys that
	// are not where the operator thinks they are.
	_, err := Parse([]byte(minimal + "\nunknown_toplevel: true\n"))
	if err == nil {
		t.Fatal("an unknown key must fail the parse")
	}
	if !strings.Contains(err.Error(), "unknown_toplevel") {
		t.Fatalf("error should name the offending key, got: %v", err)
	}
}

func TestValidationErrorsAreActionable(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			"no decoys",
			"tenant: a\nhoneyd: {decoys: []}\n",
			"no decoys",
		},
		{
			"unknown persona",
			"honeyd:\n  decoys:\n    - {id: d, persona: macos/laptop, services: [{service: ssh, port: 22}]}\n",
			"unknown persona",
		},
		{
			"unknown service",
			"honeyd:\n  decoys:\n    - {id: d, persona: linux/web, services: [{service: gopher, port: 70}]}\n",
			"unknown service",
		},
		{
			"duplicate decoy id",
			"honeyd:\n  decoys:\n" +
				"    - {id: d, persona: linux/web, services: [{service: ssh, port: 2222}]}\n" +
				"    - {id: d, persona: linux/db, services: [{service: ssh, port: 2223}]}\n",
			"duplicate decoy id",
		},
		{
			"port collision",
			"honeyd:\n  decoys:\n" +
				"    - {id: a, persona: linux/web, services: [{service: ssh, port: 2222}]}\n" +
				"    - {id: b, persona: linux/db, services: [{service: http, port: 2222}]}\n",
			"claimed by both",
		},
		{
			"bad address",
			"honeyd:\n  decoys:\n    - {id: d, persona: linux/web, addresses: [\"not-an-ip\"], services: [{service: ssh, port: 22}]}\n",
			"not a valid IP",
		},
		{
			"bad severity",
			minimal + "\nalerts: {min_severity: whenever}\n",
			"unknown severity",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestProjectionExpandsAddressesIntoListeners(t *testing.T) {
	c, err := Parse([]byte(`
honeyd:
  bind: 10.66.0.10
  decoys:
    - id: dcy-fleet
      persona: linux/web
      addresses: ["10.66.0.31", "10.66.0.32", "10.66.0.33"]
      services:
        - {service: ssh,  port: 22}
        - {service: http, port: 80}
    - id: dcy-single
      persona: linux/db
      services:
        - {service: redis, port: 6379}
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	listeners := c.Listeners()
	// Three addresses times two services, plus the single-address decoy.
	if len(listeners) != 7 {
		t.Fatalf("got %d listeners, want 7", len(listeners))
	}
	byAddr := map[string]int{}
	for _, l := range listeners {
		byAddr[l.Address]++
	}
	for _, a := range []string{"10.66.0.31", "10.66.0.32", "10.66.0.33"} {
		if byAddr[a] != 2 {
			t.Errorf("address %s has %d listeners, want 2", a, byAddr[a])
		}
	}
	// A decoy that names no addresses must not pin one: it follows the farm's
	// bind address, whatever that turns out to be.
	if byAddr[""] != 1 {
		t.Errorf("the unpinned decoy produced %d listeners, want 1", byAddr[""])
	}

	projected := c.ProjectedAddresses()
	if len(projected) != 4 {
		t.Fatalf("projected addresses = %v, want 4", projected)
	}
}

func TestSamePortOnDifferentAddressesIsAllowed(t *testing.T) {
	// This is the whole point of projection: port 22 on twenty addresses.
	_, err := Parse([]byte(`
honeyd:
  decoys:
    - {id: a, persona: linux/web, addresses: ["10.66.0.31"], services: [{service: ssh, port: 22}]}
    - {id: b, persona: linux/db,  addresses: ["10.66.0.32"], services: [{service: ssh, port: 22}]}
`))
	if err != nil {
		t.Fatalf("the same port on different addresses must be allowed: %v", err)
	}
}

func TestSameAddressAndPortTwiceIsRejected(t *testing.T) {
	_, err := Parse([]byte(`
honeyd:
  decoys:
    - {id: a, persona: linux/web, addresses: ["10.66.0.31"], services: [{service: ssh, port: 22}]}
    - {id: b, persona: linux/db,  addresses: ["10.66.0.31"], services: [{service: http, port: 22}]}
`))
	if err == nil {
		t.Fatal("two decoys on the same address and port must be rejected")
	}
}

func TestWarningsCatchDangerousDeployments(t *testing.T) {
	c, err := Parse([]byte(`
api:
  listen: "0.0.0.0:8422"
alerts:
  min_severity: low
honeyd:
  decoys:
    - {id: d, persona: linux/web, services: [{service: ssh, port: 22}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"management API", "token", "min_severity is low", "privileged ports"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings should mention %q; got:\n%s", want, warnings)
		}
	}
}

func TestLoopbackDeploymentHasNoWarnings(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("a loopback deployment on high ports should be clean, got %v", w)
	}
}

func TestEnsureSeedIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	c, _ := Parse([]byte(minimal))
	c.DataDir = dir

	if err := c.EnsureSeed(); err != nil {
		t.Fatal(err)
	}
	first := c.DeploySeed
	if first == "" {
		t.Fatal("no seed was generated")
	}

	// A second start must reuse the persisted seed: a fresh seed would change
	// every hostname and planted secret, which is exactly what gives a decoy
	// away to anyone who looked at it yesterday.
	c2, _ := Parse([]byte(minimal))
	c2.DataDir = dir
	if err := c2.EnsureSeed(); err != nil {
		t.Fatal(err)
	}
	if c2.DeploySeed != first {
		t.Fatalf("seed changed across restarts: %q then %q", first, c2.DeploySeed)
	}

	info, err := os.Stat(filepath.Join(dir, "deploy.seed"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("seed file mode = %o, want 600", perm)
	}
}

func TestParseSeverity(t *testing.T) {
	for name, want := range map[string]event.Severity{
		"info": event.SeverityInformational, "low": event.SeverityLow,
		"MEDIUM": event.SeverityMedium, " high ": event.SeverityHigh,
		"critical": event.SeverityCritical,
	} {
		got, err := ParseSeverity(name)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", name, got, err)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("an unknown severity must be rejected")
	}
}

func TestDiffListenersDetectsEveryKindOfChange(t *testing.T) {
	current := []honeyd.ListenerConfig{
		{Service: "ssh", Port: 2222, Persona: "linux/web", DecoyID: "dcy-a"},
		{Service: "http", Port: 8080, Persona: "linux/web", DecoyID: "dcy-a"},
		{Service: "redis", Port: 6380, Persona: "linux/db", DecoyID: "dcy-b"},
	}
	desired := []honeyd.ListenerConfig{
		{Service: "ssh", Port: 2222, Persona: "linux/web", DecoyID: "dcy-a"},   // unchanged
		{Service: "http", Port: 8080, Persona: "windows/dc", DecoyID: "dcy-c"}, // replaced
		{Service: "ldap", Port: 3389, Persona: "windows/dc", DecoyID: "dcy-c"}, // added
		// redis is gone
	}
	p := DiffListeners(current, desired, "0.0.0.0")

	if p.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", p.Unchanged)
	}
	byAction := map[string][]Change{}
	for _, c := range p.Changes {
		byAction[c.Action] = append(byAction[c.Action], c)
	}
	if len(byAction["add"]) != 1 || byAction["add"][0].Key != "ldap/0.0.0.0:3389" {
		t.Errorf("add = %v", byAction["add"])
	}
	if len(byAction["remove"]) != 1 || byAction["remove"][0].Key != "redis/0.0.0.0:6380" {
		t.Errorf("remove = %v", byAction["remove"])
	}
	// The address stays the same but the identity behind it changes, which an
	// attacker who already looked would notice; it must not be reported as
	// "unchanged".
	if len(byAction["replace"]) != 1 {
		t.Fatalf("replace = %v", byAction["replace"])
	}
	if !strings.Contains(byAction["replace"][0].Detail, "linux/web") {
		t.Errorf("the replace detail should name what it was: %q", byAction["replace"][0].Detail)
	}
	if p.Empty() {
		t.Error("a plan with changes must not report itself empty")
	}
}

func TestDiffListenersIsEmptyForAnIdenticalManifest(t *testing.T) {
	l := []honeyd.ListenerConfig{
		{Service: "ssh", Port: 2222, Persona: "linux/web", DecoyID: "a"},
		{Service: "http", Port: 8080, Persona: "linux/web", DecoyID: "a"},
	}
	p := DiffListeners(l, l, "0.0.0.0")
	if !p.Empty() || p.Unchanged != 2 {
		t.Fatalf("applying the same manifest twice should be a no-op: %+v", p)
	}
	if !strings.Contains(p.Summary(), "no changes") {
		t.Errorf("summary = %q", p.Summary())
	}
}

func TestDiffDistinguishesAddressesForTheSamePort(t *testing.T) {
	// Projection puts the same service and port on many addresses; they are
	// separate endpoints, not one.
	current := []honeyd.ListenerConfig{
		{Service: "ssh", Address: "10.66.0.31", Port: 22, Persona: "linux/web", DecoyID: "a"},
	}
	desired := []honeyd.ListenerConfig{
		{Service: "ssh", Address: "10.66.0.31", Port: 22, Persona: "linux/web", DecoyID: "a"},
		{Service: "ssh", Address: "10.66.0.32", Port: 22, Persona: "linux/web", DecoyID: "a"},
	}
	p := DiffListeners(current, desired, "0.0.0.0")
	if p.Unchanged != 1 || len(p.Changes) != 1 || p.Changes[0].Action != "add" {
		t.Fatalf("projection diff is wrong: %+v", p)
	}
}

func TestImmutableSettingsAreReported(t *testing.T) {
	running, _ := Parse([]byte(minimal))
	desired, _ := Parse([]byte(minimal))
	if got := Immutable(running, desired); len(got) != 0 {
		t.Fatalf("identical configurations reported %v", got)
	}

	desired.Tenant = "other"
	desired.DataDir = "/somewhere/else"
	got := Immutable(running, desired)
	if len(got) != 2 {
		t.Fatalf("expected two immutable changes, got %v", got)
	}
	// The reason matters: an operator has to understand why an apply will not
	// do what they asked.
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "evidence") {
		t.Errorf("the explanation should say what would break: %v", got)
	}
}
