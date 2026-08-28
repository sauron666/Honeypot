package fabric

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	stdin  []string
	out    map[string]string
	errFor map[string]error
}

func newRunner() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, errFor: map[string]error{}}
}

func (f *fakeRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	return f.runInput(ctx, "", name, args...)
}

func (f *fakeRunner) runInput(_ context.Context, stdin, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, key)
	if stdin != "" {
		f.stdin = append(f.stdin, stdin)
	}
	out, err := f.out[key], f.errFor[key]
	f.mu.Unlock()
	return out, err
}

func (f *fakeRunner) lastStdin() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.stdin) == 0 {
		return ""
	}
	return f.stdin[len(f.stdin)-1]
}

func nft(t *testing.T, r runner) *Nftables {
	t.Helper()
	d, err := NewNftables(map[string]any{
		"protected":      []any{"10.0.0.0/8", "192.168.50.0/24"},
		"decoy_networks": []any{"10.66.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	n := d.(*Nftables)
	n.run = r
	return n
}

func TestNftablesRefusesAGuessedScope(t *testing.T) {
	// A containment check that invents its own idea of "production" reports a
	// success it has not earned.
	if _, err := NewNftables(map[string]any{"decoy_networks": "10.66.0.0/24"}); err == nil {
		t.Fatal("a driver with no protected networks was accepted")
	}
	if _, err := NewNftables(map[string]any{"protected": "10.0.0.0/8"}); err == nil {
		t.Fatal("a driver with no decoy networks was accepted")
	}
}

func TestNftablesInstallsOneTransaction(t *testing.T) {
	r := newRunner()
	n := nft(t, r)
	if err := n.EnsureZones(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// One `nft -f -`, not a rule at a time: a segment that is half-contained
	// while the rules go in is a segment that is not contained.
	if len(r.calls) != 1 || !strings.Contains(r.calls[0], "-f -") {
		t.Fatalf("the ruleset was not applied as one transaction: %v", r.calls)
	}
	ruleset := r.lastStdin()
	for _, want := range []string{"10.0.0.0/8", "192.168.50.0/24", "10.66.0.0/24",
		"@decoy_nets", "@protected", "@isolated", "drop"} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("the ruleset is missing %q:\n%s", want, ruleset)
		}
	}
}

func TestNftablesReportsAMissingTableAsAViolationNotAnError(t *testing.T) {
	// Somebody flushed the ruleset, or the host rebooted. The answer to "is
	// this contained" is a clear no, not an error the caller might log and
	// carry on past.
	r := newRunner()
	r.errFor["nft list table inet mirage"] = errors.New("No such file or directory")
	n := nft(t, r)

	v, err := n.AssertContainment(context.Background())
	if err != nil {
		t.Fatalf("a missing table produced an error instead of a verdict: %v", err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "absent") {
		t.Fatalf("violations: %v", v)
	}
}

func TestNftablesNoticesARuleThatLostANetwork(t *testing.T) {
	// The classic drift: somebody added a production range and never told the
	// honeypot. The check must fail, not pass because a drop rule exists.
	r := newRunner()
	r.out["nft list table inet mirage"] = `table inet mirage {
  set decoy_nets { elements = { 10.66.0.0/24 } }
  set protected { elements = { 10.0.0.0/8 } }
  chain forward { ip saddr @decoy_nets ip daddr @protected drop }
}`
	n := nft(t, r)
	v, err := n.AssertContainment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "192.168.50.0/24") {
		t.Fatalf("the missing network was not reported: %v", v)
	}
}

func TestNftablesPassesAHealthyRuleset(t *testing.T) {
	r := newRunner()
	r.out["nft list table inet mirage"] = `table inet mirage {
  set decoy_nets { elements = { 10.66.0.0/24 } }
  set protected { elements = { 10.0.0.0/8, 192.168.50.0/24 } }
  chain forward { ip saddr @decoy_nets ip daddr @protected drop }
}`
	n := nft(t, r)
	v, err := n.AssertContainment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("a healthy ruleset reported violations: %v", v)
	}
}

func TestNftablesIsolateAddsTheDecoyToTheSet(t *testing.T) {
	r := newRunner()
	n := nft(t, r)
	if err := n.Isolate(context.Background(), "10.66.0.31"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || !strings.Contains(r.calls[0], "isolated { 10.66.0.31 }") {
		t.Fatalf("isolate did not touch the set: %v", r.calls)
	}
	if err := n.Isolate(context.Background(), " "); err == nil {
		t.Fatal("isolate accepted an empty address")
	}
}

// --- probe -----------------------------------------------------------------

func TestProbeReportsWhatActuallyAnswers(t *testing.T) {
	// The thing a ruleset audit cannot tell you: a real connection completed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// One reachable target and one that nothing is listening on.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := closed.Addr().String()
	closed.Close()

	d, err := NewProbe(map[string]any{
		"targets": []any{ln.Addr().String(), deadAddr},
		"timeout": "1s",
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := d.(*Probe).AssertContainment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 {
		t.Fatalf("expected exactly the reachable target to be reported: %v", v)
	}
	if !strings.Contains(v[0], ln.Addr().String()) {
		t.Fatalf("the wrong target was reported: %v", v)
	}
}

func TestProbeTreatsADroppedConnectionAsContained(t *testing.T) {
	// A timeout means something dropped the packet, which is containment
	// working. Reporting it as a violation would make the check fail every
	// time a production host was down.
	d, err := NewProbe(map[string]any{"targets": "10.255.255.1:9", "timeout": "300ms"})
	if err != nil {
		t.Fatal(err)
	}
	p := d.(*Probe)
	p.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	v, err := p.AssertContainment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("a dropped connection was reported as a violation: %v", v)
	}
}

func TestProbeRefusesToBecomeAScanner(t *testing.T) {
	many := make([]any, MaxProbeTargets+1)
	for i := range many {
		many[i] = "10.0.0.1:445"
	}
	if _, err := NewProbe(map[string]any{"targets": many}); err == nil {
		t.Fatal("a target list long enough to be a sweep was accepted")
	}
	if _, err := NewProbe(map[string]any{"targets": "not-a-pair"}); err == nil {
		t.Fatal("a malformed target was accepted")
	}
	if _, err := NewProbe(map[string]any{"targets": "10.0.0.1:70000"}); err == nil {
		t.Fatal("an out-of-range port was accepted")
	}
	if _, err := NewProbe(map[string]any{}); err == nil {
		t.Fatal("a probe driver with no targets was accepted")
	}
}

func TestProbeIsHonestAboutWhatItCannotDo(t *testing.T) {
	// A caller that believed it had isolated an owned decoy, and had not,
	// would be worse off than one that knew.
	d, err := NewProbe(map[string]any{"targets": "10.0.0.1:445"})
	if err != nil {
		t.Fatal(err)
	}
	p := d.(*Probe)
	if err := p.Isolate(context.Background(), "vm-web01"); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Isolate reported %v", err)
	}
	if err := p.KillSwitch(context.Background(), "test"); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("KillSwitch reported %v", err)
	}
}

func TestBothDriversDeclareTheFabricKind(t *testing.T) {
	for _, info := range []drivers.Info{NftablesInfo(), ProbeInfo()} {
		if info.Kind != drivers.KindFabric {
			t.Fatalf("%s declares kind %q", info.Name, info.Kind)
		}
		if info.Summary == "" {
			t.Fatalf("%s has no summary; the driver list is how an operator chooses", info.Name)
		}
	}
	// The enforcing driver must declare what it can enforce, or the planner
	// will hide the buttons it should offer.
	if !NftablesInfo().Has(drivers.CapIsolate) || !NftablesInfo().Has(drivers.CapKillSwitch) {
		t.Fatal("nftables does not declare the capabilities it implements")
	}
	if ProbeInfo().Has(drivers.CapIsolate) {
		t.Fatal("probe claims an isolation capability it does not have")
	}
}

func TestProbeTimeoutIsValidated(t *testing.T) {
	if _, err := NewProbe(map[string]any{"targets": "10.0.0.1:445", "timeout": "soon"}); err == nil {
		t.Fatal("an unparseable timeout was accepted")
	}
	d, err := NewProbe(map[string]any{"targets": "10.0.0.1:445", "timeout": "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.(*Probe).timeout; got != 5*time.Second {
		t.Fatalf("timeout is %v", got)
	}
}
