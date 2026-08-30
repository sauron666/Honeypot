// Package compliance maps MIRAGE's telemetry to regulatory controls and
// generates audit-ready evidence.
//
// Every compliance framework asks the same question in different words: "prove
// you can detect an intrusion." The evidence this platform produces — tamper-
// evident, timestamped, attributed — is exactly that proof. This package wraps
// it in the format an auditor reads: a control reference, the evidence that
// satisfies it, and the gap where it does not.
//
// Supported: NIS2, DORA, ISO 27001:2022, PCI DSS 4.0, SOC 2, IEC 62443.
package compliance

import (
	"fmt"
	"strings"
	"time"
)

// Control is one regulatory requirement.
type Control struct {
	Framework   string `json:"framework"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Satisfied   bool   `json:"satisfied"`
	Evidence    string `json:"evidence,omitempty"`
}

// Capabilities describes what the deployment provides.
type Capabilities struct {
	HasDecoys       bool
	HasHashChain    bool
	HasAlerts       bool
	HasEngagements  bool
	HasForge        bool
	HasAssure       bool
	HasFingerprint  bool
	HasOverlay      bool
	HasVMFarm       bool
	HasBreadcrumbs  bool
	HasTokens       bool
	HasKerberos     bool
	HasRansomware   bool
	HasEconomics    bool
	DecoyCount      int
	EngagementCount int
	AlertCount      int
	SinkCount       int
	FabricDriver    string
	EvidenceFile    string
	DeploymentDate  time.Time
}

// Audit generates the control mapping for all supported frameworks.
func Audit(cap Capabilities) []Control {
	var out []Control
	out = append(out, nis2Controls(cap)...)
	out = append(out, doraControls(cap)...)
	out = append(out, iso27001Controls(cap)...)
	out = append(out, pciControls(cap)...)
	out = append(out, soc2Controls(cap)...)
	out = append(out, iec62443Controls(cap)...)
	return out
}

// Summary returns a per-framework pass/total count.
type Summary struct {
	Framework string `json:"framework"`
	Passed    int    `json:"passed"`
	Total     int    `json:"total"`
	Ratio     string `json:"ratio"`
}

// Summarize groups controls by framework.
func Summarize(controls []Control) []Summary {
	byFw := map[string]*Summary{}
	for _, c := range controls {
		s, ok := byFw[c.Framework]
		if !ok {
			s = &Summary{Framework: c.Framework}
			byFw[c.Framework] = s
		}
		s.Total++
		if c.Satisfied {
			s.Passed++
		}
	}
	var out []Summary
	for _, fw := range []string{"NIS2", "DORA", "ISO 27001:2022", "PCI DSS 4.0", "SOC 2", "IEC 62443"} {
		if s, ok := byFw[fw]; ok {
			s.Ratio = fmt.Sprintf("%d/%d", s.Passed, s.Total)
			out = append(out, *s)
		}
	}
	return out
}

func sat(ok bool, evidence string) (bool, string) {
	if !ok {
		return false, ""
	}
	return true, evidence
}

func nis2Controls(c Capabilities) []Control {
	return []Control{
		{Framework: "NIS2", ID: "Art.21(b)", Title: "Incident handling",
			Satisfied: c.HasEngagements && c.HasAlerts,
			Evidence:  condStr(c.HasEngagements && c.HasAlerts, "Engagement tracker stitches events into attributed incidents; alerts forward to SIEM")},
		{Framework: "NIS2", ID: "Art.21(d)", Title: "Supply chain security",
			Satisfied: c.HasBreadcrumbs || c.HasTokens,
			Evidence:  condStr(c.HasBreadcrumbs || c.HasTokens, "Breadcrumbs and honeytokens planted on endpoints detect lateral movement from supply-chain compromise")},
		{Framework: "NIS2", ID: "Art.21(e)", Title: "Security in acquisition and development",
			Satisfied: c.HasHashChain,
			Evidence:  condStr(c.HasHashChain, "Evidence chain is append-only with SHA-256 hash chain; tamper detection is built-in")},
		{Framework: "NIS2", ID: "Art.21(g)", Title: "Cybersecurity assessment",
			Satisfied: c.HasAssure && c.HasFingerprint,
			Evidence:  condStr(c.HasAssure && c.HasFingerprint, "Self-test (miragectl assure) and detectability scoring (miragectl fingerprint) run continuously")},
		{Framework: "NIS2", ID: "Art.23", Title: "Reporting obligations",
			Satisfied: c.HasForge && c.HasEconomics,
			Evidence:  condStr(c.HasForge && c.HasEconomics, "Detection forge generates Sigma/Suricata/YARA/STIX + incident report; economics provides quantitative metrics")},
	}
}

func doraControls(c Capabilities) []Control {
	return []Control{
		{Framework: "DORA", ID: "Art.10", Title: "ICT-related incident detection",
			Satisfied: c.HasDecoys && c.HasAlerts && c.SinkCount > 0,
			Evidence:  condStr(c.HasDecoys && c.HasAlerts && c.SinkCount > 0, fmt.Sprintf("%d decoys with %d alert sinks; any contact is a confirmed incident (0 false positives)", c.DecoyCount, c.SinkCount))},
		{Framework: "DORA", ID: "Art.11", Title: "ICT-related incident response",
			Satisfied: c.HasEngagements && c.HasForge,
			Evidence:  condStr(c.HasEngagements && c.HasForge, "Engagements provide timeline and attribution; forge generates detection artefacts for the SOC")},
		{Framework: "DORA", ID: "Art.25", Title: "Threat-led penetration testing",
			Satisfied: c.HasAssure,
			Evidence:  condStr(c.HasAssure, "miragectl assure performs automated threat-led testing of the deception deployment itself")},
	}
}

func iso27001Controls(c Capabilities) []Control {
	return []Control{
		{Framework: "ISO 27001:2022", ID: "A.8.16", Title: "Monitoring activities",
			Satisfied: c.HasDecoys && c.HasHashChain,
			Evidence:  condStr(c.HasDecoys && c.HasHashChain, "Decoys produce tamper-evident telemetry with hash-chain integrity")},
		{Framework: "ISO 27001:2022", ID: "A.5.7", Title: "Threat intelligence",
			Satisfied: c.HasForge,
			Evidence:  condStr(c.HasForge, "Detection forge converts observations into actionable threat intelligence (Sigma, STIX, IOCs)")},
		{Framework: "ISO 27001:2022", ID: "A.5.25", Title: "Assessment of information security events",
			Satisfied: c.HasEngagements && c.HasEconomics,
			Evidence:  condStr(c.HasEngagements && c.HasEconomics, "Engagements automatically assess and score incidents; economics quantifies attacker time consumed")},
		{Framework: "ISO 27001:2022", ID: "A.8.7", Title: "Protection against malware",
			Satisfied: c.HasRansomware,
			Evidence:  condStr(c.HasRansomware, "Six independent ransomware signals + tarpit + ransom note extraction")},
	}
}

func pciControls(c Capabilities) []Control {
	return []Control{
		{Framework: "PCI DSS 4.0", ID: "11.5", Title: "Network intrusion detection",
			Satisfied: c.HasDecoys && c.HasAlerts,
			Evidence:  condStr(c.HasDecoys && c.HasAlerts, "Decoys act as network-level intrusion detection with zero false positives")},
		{Framework: "PCI DSS 4.0", ID: "10.2", Title: "Audit log implementation",
			Satisfied: c.HasHashChain,
			Evidence:  condStr(c.HasHashChain, "Append-only evidence file with SHA-256 hash chain provides tamper-evident audit logging")},
		{Framework: "PCI DSS 4.0", ID: "12.10", Title: "Incident response plan",
			Satisfied: c.HasForge && c.HasEngagements,
			Evidence:  condStr(c.HasForge && c.HasEngagements, "Forge generates incident report + IOCs; engagements provide the timeline")},
	}
}

func soc2Controls(c Capabilities) []Control {
	return []Control{
		{Framework: "SOC 2", ID: "CC7.2", Title: "Monitoring of system components",
			Satisfied: c.HasDecoys && c.HasAlerts && c.HasHashChain,
			Evidence:  condStr(c.HasDecoys && c.HasAlerts && c.HasHashChain, "Continuous deception monitoring with tamper-evident evidence chain and real-time alerts")},
		{Framework: "SOC 2", ID: "CC7.3", Title: "Detection of unauthorized activity",
			Satisfied: c.HasDecoys,
			Evidence:  condStr(c.HasDecoys, "Any interaction with a decoy is unauthorized by definition — zero legitimate use, zero false positives")},
	}
}

func iec62443Controls(c Capabilities) []Control {
	return []Control{
		{Framework: "IEC 62443", ID: "SR 3.3", Title: "Security functionality verification",
			Satisfied: c.HasAssure && c.HasFingerprint,
			Evidence:  condStr(c.HasAssure && c.HasFingerprint, "Self-test verifies detection capability; fingerprint scores detectability of each decoy")},
		{Framework: "IEC 62443", ID: "SR 6.1", Title: "Audit log accessibility",
			Satisfied: c.HasHashChain,
			Evidence:  condStr(c.HasHashChain, "Evidence file is append-only with cryptographic integrity; miragectl verify checks the chain")},
	}
}

func condStr(ok bool, s string) string {
	if !ok {
		return ""
	}
	return s
}

// ReportMarkdown generates a Markdown compliance report.
func ReportMarkdown(controls []Control, cap Capabilities) string {
	var b strings.Builder
	b.WriteString("# MIRAGE Compliance Evidence Report\n\n")
	b.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Deployment: %d decoys, evidence file: %s\n\n", cap.DecoyCount, cap.EvidenceFile))

	summaries := Summarize(controls)
	b.WriteString("## Summary\n\n")
	b.WriteString("| Framework | Passed | Total | Coverage |\n|---|---|---|---|\n")
	for _, s := range summaries {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %s |\n", s.Framework, s.Passed, s.Total, s.Ratio))
	}

	b.WriteString("\n## Control Details\n\n")
	currentFw := ""
	for _, c := range controls {
		if c.Framework != currentFw {
			currentFw = c.Framework
			b.WriteString(fmt.Sprintf("\n### %s\n\n", currentFw))
		}
		status := "PASS"
		if !c.Satisfied {
			status = "GAP"
		}
		b.WriteString(fmt.Sprintf("**[%s] %s %s** — %s\n", status, c.ID, c.Title, c.Description))
		if c.Evidence != "" {
			b.WriteString(fmt.Sprintf("  Evidence: %s\n\n", c.Evidence))
		} else {
			b.WriteString("  *No evidence available — this control requires additional configuration.*\n\n")
		}
	}
	return b.String()
}
