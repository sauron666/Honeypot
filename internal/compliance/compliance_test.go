package compliance

import (
	"strings"
	"testing"
)

func full() Capabilities {
	return Capabilities{
		HasDecoys: true, HasHashChain: true, HasAlerts: true, HasEngagements: true,
		HasForge: true, HasAssure: true, HasFingerprint: true, HasTokens: true,
		HasKerberos: true, HasRansomware: true, HasEconomics: true,
		HasOverlay: true, HasVMFarm: true, HasBreadcrumbs: true,
		DecoyCount: 6, EngagementCount: 3, AlertCount: 5, SinkCount: 2,
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

func TestEachFrameworkMapsToSpecificControls(t *testing.T) {
	controls := Audit(full())
	byFw := map[string][]Control{}
	for _, c := range controls {
		byFw[c.Framework] = append(byFw[c.Framework], c)
	}
	for fw, ctrls := range byFw {
		for _, c := range ctrls {
			if c.ID == "" {
				t.Fatalf("framework %s has a control with no ID", fw)
			}
			if c.Title == "" {
				t.Fatalf("framework %s control %s has no title", fw, c.ID)
			}
		}
	}
}

func TestSummarizePassFailMatchesControls(t *testing.T) {
	controls := Audit(full())
	summaries := Summarize(controls)

	byFw := map[string]struct{ pass, total int }{}
	for _, c := range controls {
		s := byFw[c.Framework]
		s.total++
		if c.Satisfied {
			s.pass++
		}
		byFw[c.Framework] = s
	}
	for _, s := range summaries {
		expected := byFw[s.Framework]
		if s.Passed != expected.pass || s.Total != expected.total {
			t.Fatalf("framework %s: summary says %d/%d, controls say %d/%d",
				s.Framework, s.Passed, s.Total, expected.pass, expected.total)
		}
	}
}

func TestBareDeploymentProducesGaps(t *testing.T) {
	bare := Capabilities{}
	controls := Audit(bare)
	satisfied := 0
	for _, c := range controls {
		if c.Satisfied {
			satisfied++
		}
	}
	if satisfied != 0 {
		t.Fatalf("a bare deployment should satisfy 0 controls, got %d", satisfied)
	}
}

func TestSatisfiedControlsHaveEvidence(t *testing.T) {
	controls := Audit(full())
	for _, c := range controls {
		if c.Satisfied && c.Evidence == "" {
			t.Fatalf("control %s %s is satisfied but has no evidence", c.Framework, c.ID)
		}
		if !c.Satisfied && c.Evidence != "" {
			t.Fatalf("control %s %s is not satisfied but has evidence: %q", c.Framework, c.ID, c.Evidence)
		}
	}
}

func TestReportIncludesAllFrameworkSections(t *testing.T) {
	report := ReportMarkdown(Audit(full()), full())
	for _, fw := range []string{"NIS2", "DORA", "ISO 27001:2022", "PCI DSS 4.0", "SOC 2", "IEC 62443"} {
		if !strings.Contains(report, fw) {
			t.Fatalf("the report does not have a section for %s", fw)
		}
	}
	if !strings.Contains(report, "PASS") {
		t.Fatal("the report has no PASS markers")
	}
}

func TestPartialCapabilitiesReduceSomeBothNothAll(t *testing.T) {
	partial := Capabilities{
		HasDecoys:    true,
		HasHashChain: true,
	}
	controls := Audit(partial)
	sat, unsat := 0, 0
	for _, c := range controls {
		if c.Satisfied {
			sat++
		} else {
			unsat++
		}
	}
	if sat == 0 {
		t.Fatal("hash chain + decoys should satisfy at least one control")
	}
	if unsat == 0 {
		t.Fatal("partial capabilities should still leave some controls unsatisfied")
	}
}
