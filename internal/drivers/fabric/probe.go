package fabric

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// ProbeInfo describes the verification-only fabric driver.
func ProbeInfo() drivers.Info {
	return drivers.Info{
		Name: "probe",
		Kind: drivers.KindFabric,
		Summary: "Verifies containment by testing it: from where the decoys run, it tries to open " +
			"the connections that must fail. Enforces nothing, and works on any network, " +
			"including ones MIRAGE has no control over.",
		Capabilities: []drivers.Capability{drivers.CapACL},
	}
}

// Probe answers "is this contained" by trying, rather than by reading rules.
//
// A ruleset says what somebody intended. A successful TCP handshake from the
// decoy host to a production database says what is actually true, and the two
// differ far more often than anyone expects: a rule on the wrong interface, a
// route that survived a maintenance window, a hypervisor bridge nobody
// remembered. This driver is the one that catches those.
//
// It is deliberately narrow. It connects only to the addresses and ports the
// operator listed as things a decoy must never reach, it sends no payload, it
// closes immediately, and it never discovers targets of its own. A tool that
// scanned would be a tool that eventually scanned somebody else's network.
type Probe struct {
	// targets are host:port pairs that must be unreachable from here.
	targets []string
	timeout time.Duration
	// dial is injectable for tests.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	isolated []string
}

// MaxProbeTargets bounds the check. Containment is proven by a handful of
// representative targets; a list long enough to look like a scan is a
// configuration mistake worth refusing.
const MaxProbeTargets = 64

// NewProbe builds the driver. Config keys: "targets" (required, host:port
// pairs that must be unreachable), "timeout" (default 2s).
func NewProbe(cfg map[string]any) (drivers.Driver, error) {
	targets := stringsFrom(cfg, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("fabric/probe: \"targets\" is required: the host:port pairs a decoy " +
			"must never reach, for example your domain controller on 389 and your backup " +
			"server on 445")
	}
	if len(targets) > MaxProbeTargets {
		return nil, fmt.Errorf("fabric/probe: %d targets is more than the %d this check allows; "+
			"containment is proven with representative targets, not with a sweep",
			len(targets), MaxProbeTargets)
	}
	for _, t := range targets {
		host, port, err := net.SplitHostPort(t)
		if err != nil || host == "" {
			return nil, fmt.Errorf("fabric/probe: %q is not a host:port pair", t)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("fabric/probe: %q has an invalid port", t)
		}
	}
	timeout := 2 * time.Second
	if v, ok := cfg["timeout"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("fabric/probe: timeout %q: %w", v, err)
		}
		timeout = d
	}
	d := &net.Dialer{}
	return &Probe{
		targets: targets, timeout: timeout,
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}, nil
}

func (p *Probe) Info() drivers.Info          { return ProbeInfo() }
func (p *Probe) Probe(context.Context) error { return nil }
func (p *Probe) Close() error                { return nil }

// EnsureZones is a no-op: this driver observes, it does not configure.
func (p *Probe) EnsureZones(context.Context, []drivers.Zone) error { return nil }

// AssertContainment reports every target that answered.
//
// Only a completed connection is a violation. A refused connection means
// something rejected it, and a timeout means something dropped it; both are
// containment doing its job. Treating a timeout as a violation would make the
// check fail whenever a production host happened to be down, and a check that
// cries wolf is a check that gets disabled.
func (p *Probe) AssertContainment(ctx context.Context) ([]string, error) {
	type result struct{ msg string }
	results := make(chan result, len(p.targets))

	var wg sync.WaitGroup
	for _, target := range p.targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, p.timeout)
			defer cancel()
			conn, err := p.dial(dctx, "tcp", target)
			if err != nil {
				return
			}
			conn.Close()
			results <- result{fmt.Sprintf(
				"a decoy host can open a TCP connection to %s, which containment forbids", target)}
		}(target)
	}
	wg.Wait()
	close(results)

	var violations []string
	for r := range results {
		violations = append(violations, r.msg)
	}
	sort.Strings(violations)
	return violations, nil
}

// Isolate is recorded but not enforced: this driver has no control plane.
// Saying so out loud matters, because a caller that believed it had isolated a
// compromised decoy and had not would be worse off than one that knew.
func (p *Probe) Isolate(_ context.Context, decoyID string) error {
	p.mu.Lock()
	p.isolated = append(p.isolated, decoyID)
	p.mu.Unlock()
	return fmt.Errorf("fabric/probe: %s must be isolated by hand: %w", decoyID, ErrNotSupported)
}

// KillSwitch is likewise not available.
func (p *Probe) KillSwitch(_ context.Context, reason string) error {
	return fmt.Errorf("fabric/probe: cannot cut the decoy segment (%s); "+
		"pull the link or use an enforcing fabric driver: %w", reason, ErrNotSupported)
}

// Targets reports what this driver checks, for the console and doctor.
func (p *Probe) Targets() []string { return append([]string(nil), p.targets...) }

// String is what doctor prints.
func (p *Probe) String() string {
	return "probe(" + strings.Join(p.targets, ", ") + ")"
}

var _ drivers.FabricDriver = (*Probe)(nil)
