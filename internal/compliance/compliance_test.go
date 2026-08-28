package compliance

import (
	"strings"
	"testing"
)

func full() Capabilities {
	return Capabilities{
		HasDecoys: true, HasHashChain: true, HasAlerts: true, HasEngagements: true,
		HasForge: true, HasAssure: true, HasFingerprint: true, HasTokens: true,
		HasKerberos: true, HasRansomware: true, DecoyCount: 6, SinkCount: 2,
		FabricDriver: "nftables", EvidenceFile: "evidence.jsonl",
	}
}

func TestAuditCoversEveryFramework(t *testing.T) {
	controls := Audit(full())
	if len(controls) == 0 {
		t.Fatal("no controls produced")
	}
	// Every framework the summariser knows must appear.
	seen := map[string]bool{}
	for _, c := range controls {
		seen[c.Framework] = true
	}
	for _, fw := range []string{"NIS2", "DORA", "ISO 27001:2022", "PCI DSS 4.0", "SOC 2", "IEC 62443"} {
		if !seen[fw] {
			t.Fatalf("framework %q is missing from the audit", fw)
		}
	}
}

func TestCapabilitiesChangeSatisfaction(t *testing.T) {
	// The audit must reflect reality: turning off the hash chain must drop the
	// controls that depend on tamper-evident evidence. A compliance report that
	// says "satisfied" regardless of configuration is worse than none.
	withChain := Summarize(Audit(full()))
	bare := full()
	bare.HasHashChain = false
	bare.HasDecoys = false
	bare.HasAlerts = false
	without := Summarize(Audit(bare))

	sum := func(ss []Summary) (pass int) {
		for _, s := range ss {
			pass += s.Passed
		}
		return
	}
	if sum(without) >= sum(withChain) {
		t.Fatalf("removing capabilities did not reduce satisfied controls: %d vs %d",
			sum(without), sum(withChain))
	}
}

func TestReportMarkdownIsWellFormed(t *testing.T) {
	report := ReportMarkdown(Audit(full()), full())
	if !strings.Contains(report, "#") {
		t.Fatal("the report has no markdown headings")
	}
	for _, fw := range []string{"NIS2", "DORA"} {
		if !strings.Contains(report, fw) {
			t.Fatalf("the report does not mention %s", fw)
		}
	}
}
