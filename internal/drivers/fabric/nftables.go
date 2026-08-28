package fabric

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// NftablesInfo describes the packet-filter fabric driver.
func NftablesInfo() drivers.Info {
	return drivers.Info{
		Name: "nftables",
		Kind: drivers.KindFabric,
		Summary: "Containment on a Linux host with nftables: a dedicated table that drops decoy " +
			"traffic towards protected networks, per-decoy isolation and a kill switch. " +
			"Verifies the rules it relies on rather than assuming somebody configured them.",
		Capabilities: []drivers.Capability{
			drivers.CapSegments, drivers.CapACL, drivers.CapIsolate, drivers.CapKillSwitch,
		},
	}
}

// Nftables drives nft(8).
//
// It owns one table, `inet mirage`, and nothing outside it. A deception
// platform that edits an operator's existing firewall is a deception platform
// that gets removed after the first outage.
type Nftables struct {
	nft string
	// Protected are the networks a decoy must never reach: production, in
	// whatever CIDRs this site uses. There is no default. Guessing RFC1918
	// would be wrong in a cloud estate and dangerously incomplete in a large
	// one, and a containment check with a made-up scope is worse than none,
	// because it reports success.
	protected []string
	// DecoyNets are the source networks the decoys live in.
	decoyNets []string
	run       runner

	mu       sync.Mutex
	isolated map[string]bool
}

// NewNftables builds the driver. Config keys: "protected" (required, list of
// CIDRs), "decoy_networks" (required, list of CIDRs), "nft" (binary path).
func NewNftables(cfg map[string]any) (drivers.Driver, error) {
	protected := stringsFrom(cfg, "protected")
	decoys := stringsFrom(cfg, "decoy_networks")
	if len(protected) == 0 {
		return nil, fmt.Errorf("fabric/nftables: \"protected\" is required: list the networks a " +
			"decoy must never reach, because a containment check with a guessed scope reports " +
			"success it has not earned")
	}
	if len(decoys) == 0 {
		return nil, fmt.Errorf("fabric/nftables: \"decoy_networks\" is required: " +
			"the source networks the decoys live in")
	}
	return &Nftables{
		nft:       stringFrom(cfg, "nft", "nft"),
		protected: protected,
		decoyNets: decoys,
		run:       execRunner{timeout: 30 * time.Second},
		isolated:  map[string]bool{},
	}, nil
}

func (n *Nftables) Info() drivers.Info { return NftablesInfo() }

func (n *Nftables) Probe(ctx context.Context) error {
	if !binaryExists(n.nft) {
		return fmt.Errorf("fabric/nftables: %q not found on PATH", n.nft)
	}
	if _, err := n.run.run(ctx, n.nft, "--version"); err != nil {
		return fmt.Errorf("fabric/nftables: %w", err)
	}
	return nil
}

func (n *Nftables) Close() error { return nil }

// EnsureZones installs the containment table.
//
// The rules are written as a single `nft -f -` transaction, so a failure
// halfway through leaves the previous ruleset intact rather than a half-open
// decoy segment.
func (n *Nftables) EnsureZones(ctx context.Context, _ []drivers.Zone) error {
	var b strings.Builder
	b.WriteString("table inet mirage {\n")
	b.WriteString("  set decoy_nets { type ipv4_addr; flags interval; elements = { " +
		strings.Join(n.decoyNets, ", ") + " } }\n")
	b.WriteString("  set protected { type ipv4_addr; flags interval; elements = { " +
		strings.Join(n.protected, ", ") + " } }\n")
	// isolated is filled at runtime by Isolate; it must exist from the start so
	// that isolating a decoy during an incident is one command, not two.
	b.WriteString("  set isolated { type ipv4_addr; }\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority -10; policy accept;\n")
	b.WriteString("    ip saddr @isolated drop\n")
	b.WriteString("    ip daddr @isolated drop\n")
	b.WriteString("    ip saddr @decoy_nets ip daddr @protected " +
		"log prefix \"mirage-containment \" drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")

	if _, err := n.nftApply(ctx, b.String()); err != nil {
		return fmt.Errorf("fabric/nftables: install containment table: %w", err)
	}
	return nil
}

// AssertContainment reads back the live ruleset and reports what is missing.
//
// It deliberately re-reads rather than trusting that EnsureZones ran: between
// then and now somebody may have flushed the ruleset, restarted the firewall
// or rebooted the host, and the whole point of asserting is to catch that.
func (n *Nftables) AssertContainment(ctx context.Context) ([]string, error) {
	out, err := n.run.run(ctx, n.nft, "list", "table", "inet", "mirage")
	if err != nil {
		// A missing table is a violation, not an error: the answer to
		// "is this contained" is a clear no.
		return []string{"the inet mirage table is absent: nothing is enforcing containment " +
			"(run the director once to install it, or check that nftables is loaded)"}, nil
	}

	var violations []string
	if !strings.Contains(out, "@decoy_nets") || !strings.Contains(out, "@protected") {
		violations = append(violations,
			"the containment rule matching decoy sources against protected networks is missing")
	}
	if !strings.Contains(out, "drop") {
		violations = append(violations, "the containment table contains no drop rule")
	}
	for _, cidr := range n.protected {
		if !strings.Contains(out, cidr) {
			violations = append(violations,
				fmt.Sprintf("protected network %s is not in the live ruleset", cidr))
		}
	}
	for _, cidr := range n.decoyNets {
		if !strings.Contains(out, cidr) {
			violations = append(violations,
				fmt.Sprintf("decoy network %s is not in the live ruleset", cidr))
		}
	}
	return violations, nil
}

// Isolate cuts one decoy off in both directions.
func (n *Nftables) Isolate(ctx context.Context, decoyIP string) error {
	if strings.TrimSpace(decoyIP) == "" {
		return fmt.Errorf("fabric/nftables: isolate needs the decoy's address")
	}
	if _, err := n.run.run(ctx, n.nft, "add", "element", "inet", "mirage", "isolated",
		"{ "+decoyIP+" }"); err != nil {
		return fmt.Errorf("fabric/nftables: isolate %s: %w", decoyIP, err)
	}
	n.mu.Lock()
	n.isolated[decoyIP] = true
	n.mu.Unlock()
	return nil
}

// KillSwitch drops everything leaving the decoy networks.
//
// It is the answer to "something is very wrong and I do not yet know what".
// Emulated decoys keep answering, because they never needed to reach anything;
// full-OS decoys go silent, which is the intended trade.
func (n *Nftables) KillSwitch(ctx context.Context, reason string) error {
	rule := "table inet mirage {\n" +
		"  chain killswitch {\n" +
		"    type filter hook forward priority -100; policy accept;\n" +
		"    ip saddr @decoy_nets log prefix \"mirage-killswitch \" drop\n" +
		"    ip daddr @decoy_nets log prefix \"mirage-killswitch \" drop\n" +
		"  }\n" +
		"}\n"
	if _, err := n.nftApply(ctx, rule); err != nil {
		return fmt.Errorf("fabric/nftables: kill switch (%s): %w", reason, err)
	}
	return nil
}

// nftApply feeds a ruleset to nft as one transaction. `nft -f -` either
// applies all of it or none of it, which is the only acceptable behaviour for
// rules whose job is to keep an owned machine off a production network.
func (n *Nftables) nftApply(ctx context.Context, ruleset string) (string, error) {
	return n.run.runInput(ctx, ruleset, n.nft, "-f", "-")
}

var _ drivers.FabricDriver = (*Nftables)(nil)
