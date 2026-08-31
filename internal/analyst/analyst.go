// Package analyst turns a closed engagement into human-readable prose: a short
// summary, an incident-report draft, and a suggested Sigma rule.
//
// It exists to save an analyst the first hour of writing, not to replace their
// judgement. Two rules are absolute. First, the analyst is NEVER in the alerting
// path -- alerts come from the evidence chain and the alert package, which owe
// nothing to any model. Second, EVERY output is stamped RequiresReview: an
// LLM (and even a template) can be confidently wrong, and a deception report
// that goes to a court or a customer must have had a human read it.
//
// The default implementation is Template: fully offline, deterministic, no
// network. It is the air-gap fallback and the thing an LLM output is compared
// against. The LLM implementation (llm.go) is optional and, on any failure,
// the caller falls back here.
package analyst

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sauron666/Honeypot/internal/engagement"
)

// Narrative is what an analyst produces from one engagement. RequiresReview is
// always true by construction: nothing here is a finished artefact, it is a
// draft for a human to check.
type Narrative struct {
	Summary        string `json:"summary"`
	ReportDraft    string `json:"report_draft"`
	SuggestedSigma string `json:"suggested_sigma"`
	RequiresReview bool   `json:"requires_review"`
	// Source records who wrote this: "template" for the offline synthesiser,
	// "llm:<model>" for a language model. An operator must be able to tell a
	// deterministic summary from a generated one.
	Source string `json:"source"`
}

// Analyst produces a Narrative from an engagement.
type Analyst interface {
	Analyze(ctx context.Context, eng engagement.Engagement) (Narrative, error)
}

// Template is the offline, deterministic analyst. It synthesises real prose
// from the engagement fields -- no network, no model, no state -- so it works
// in an air-gapped deployment and gives the same output for the same input.
//
// It is honest about what it is: it does string synthesis from the recorded
// evidence, it does not reason. That is why its narrative sticks to what the
// fields say and never speculates about intent.
type Template struct{}

// Analyze builds a summary, a markdown report draft, and a suggested Sigma rule
// from the engagement. It never errors: an offline fallback that can fail is not
// a fallback.
func (Template) Analyze(_ context.Context, eng engagement.Engagement) (Narrative, error) {
	return Narrative{
		Summary:        templateSummary(eng),
		ReportDraft:    templateReport(eng),
		SuggestedSigma: templateSigma(eng),
		RequiresReview: true,
		Source:         "template",
	}, nil
}

// templateSummary is a one-paragraph triage line built from the strongest
// signals present. The order encodes severity: touching bait beats getting in,
// getting in beats knocking.
func templateSummary(eng engagement.Engagement) string {
	var b strings.Builder
	src := eng.SrcIP
	if src == "" {
		src = "an unidentified source"
	}
	fmt.Fprintf(&b, "Source %s opened engagement %s", src, eng.ID)
	if n := len(eng.Decoys); n > 0 {
		fmt.Fprintf(&b, " against %d decoy(s)", n)
	}
	fmt.Fprintf(&b, ", generating %d event(s) at a peak severity of %s.", eng.Events, eng.MaxSeverity)

	switch {
	case len(eng.HoneytokensHit) > 0:
		b.WriteString(" The actor read planted honeytokens, so this is a confirmed hands-on intrusion, not a scan.")
	case len(eng.PayloadURLs) > 0:
		b.WriteString(" The actor attempted to stage a remote payload on a decoy.")
	case eng.Authenticated && eng.Commands > 0:
		b.WriteString(" The actor authenticated and ran commands: a hands-on-keyboard session.")
	case eng.Authenticated:
		b.WriteString(" The actor authenticated to a decoy.")
	case eng.Credentials > 3:
		b.WriteString(" The activity looks like a credential brute force.")
	case eng.Credentials > 0:
		b.WriteString(" The actor offered credentials to a decoy.")
	default:
		b.WriteString(" The activity so far is reconnaissance.")
	}
	fmt.Fprintf(&b, " Risk score %d/100.", eng.RiskScore)
	return b.String()
}

// templateReport is the markdown draft. It is structured the way an incident
// report reads: what happened, the evidence, the ATT&CK mapping, and an
// assessment that stays inside the facts.
func templateReport(eng engagement.Engagement) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Incident report draft: engagement %s\n\n", eng.ID)
	b.WriteString("> DRAFT -- requires human review. Generated offline from decoy evidence.\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString(templateSummary(eng))
	b.WriteString("\n\n")

	b.WriteString("## What happened\n\n")
	fmt.Fprintf(&b, "- Source: %s\n", orNA(eng.SrcIP))
	fmt.Fprintf(&b, "- First seen: %s\n", eng.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "- Last seen: %s\n", eng.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC"))
	if eng.AttackerSummary != "" {
		fmt.Fprintf(&b, "- Attacker time consumed: %s\n", eng.AttackerSummary)
	}
	fmt.Fprintf(&b, "- Decoys touched: %s\n", listOrNone(eng.Decoys))
	fmt.Fprintf(&b, "- Services probed: %s\n", listOrNone(eng.Services))
	b.WriteString("\n")

	b.WriteString("## Evidence\n\n")
	fmt.Fprintf(&b, "- Events recorded: %d (peak severity %s)\n", eng.Events, eng.MaxSeverity)
	fmt.Fprintf(&b, "- Credentials offered: %d\n", eng.Credentials)
	fmt.Fprintf(&b, "- Authenticated to a decoy: %s\n", yesNo(eng.Authenticated))
	fmt.Fprintf(&b, "- Commands executed: %d\n", eng.Commands)
	if len(eng.HoneytokensHit) > 0 {
		fmt.Fprintf(&b, "- Honeytokens read: %s\n", listOrNone(eng.HoneytokensHit))
	}
	if len(eng.PayloadURLs) > 0 {
		fmt.Fprintf(&b, "- Payload URLs observed: %s\n", listOrNone(eng.PayloadURLs))
	}
	b.WriteString("\n")

	b.WriteString("## ATT&CK techniques\n\n")
	if len(eng.Techniques) == 0 {
		b.WriteString("- None mapped.\n")
	} else {
		for _, t := range sortedCopy(eng.Techniques) {
			fmt.Fprintf(&b, "- %s\n", t)
		}
	}
	b.WriteString("\n")

	b.WriteString("## Assessment\n\n")
	b.WriteString(assessment(eng))
	b.WriteString("\n\n")

	b.WriteString("## Recommended next steps\n\n")
	b.WriteString("1. Confirm the source IP is not a sanctioned scanner or internal tool.\n")
	b.WriteString("2. Hunt for the observed techniques and indicators on production assets.\n")
	b.WriteString("3. Review and, if appropriate, deploy the suggested detection below after tuning.\n\n")

	b.WriteString("---\n\n")
	b.WriteString("_This report was drafted automatically and MUST be reviewed by an analyst before any external use._\n")
	return b.String()
}

// assessment stays strictly inside the recorded facts. A template that
// speculated about attribution or intent would be dishonest.
func assessment(eng engagement.Engagement) string {
	switch {
	case len(eng.HoneytokensHit) > 0:
		return "The actor read credentials that exist only inside the deception fabric. No legitimate user ever touches them, so this is a high-confidence intrusion. The read honeytokens are trip-wires: any later use of them elsewhere ties this actor to that activity."
	case eng.Authenticated && eng.Commands > 0:
		return "The actor authenticated to a decoy and executed commands. Because the decoy has no production role, every action is attributable to the intruder rather than mixed with legitimate traffic."
	case eng.Authenticated:
		return "The actor authenticated to a decoy but was not observed running commands before the engagement went quiet."
	case eng.Credentials > 0:
		return "The actor offered credentials but did not authenticate successfully within this engagement. This is consistent with credential guessing or spraying."
	default:
		return "The activity is limited to reconnaissance: contact with one or more decoys without successful authentication. It is still notable because the decoys have no legitimate users."
	}
}

// templateSigma derives a minimal, clearly-marked-draft Sigma rule from the
// techniques and services. It is deliberately conservative and never claims to
// be production-ready -- the forge package is where validated rules come from;
// this is a starting point for the analyst.
func templateSigma(eng engagement.Engagement) string {
	var b strings.Builder
	title := "Decoy interaction from " + orNA(eng.SrcIP)

	b.WriteString("title: " + title + "\n")
	b.WriteString("status: experimental\n")
	fmt.Fprintf(&b, "description: DRAFT rule suggested from decoy engagement %s. Requires human review before deployment.\n", eng.ID)

	tags := sigmaTags(eng.Techniques)
	if len(tags) > 0 {
		b.WriteString("tags:\n")
		for _, t := range tags {
			fmt.Fprintf(&b, "    - %s\n", t)
		}
	}

	b.WriteString("logsource:\n")
	b.WriteString("    category: network_connection\n")
	b.WriteString("detection:\n")
	b.WriteString("    selection:\n")
	if eng.SrcIP != "" {
		fmt.Fprintf(&b, "        src_ip: '%s'\n", eng.SrcIP)
	}
	if svcs := sortedCopy(eng.Services); len(svcs) > 0 {
		b.WriteString("        service:\n")
		for _, s := range svcs {
			fmt.Fprintf(&b, "            - '%s'\n", s)
		}
	}
	b.WriteString("    condition: selection\n")
	b.WriteString("falsepositives:\n")
	b.WriteString("    - Sanctioned vulnerability scanners\n")
	b.WriteString("level: high\n")
	return b.String()
}

// sigmaTags maps ATT&CK technique ids to Sigma's lowercase attack.t#### tags.
func sigmaTags(techniques []string) []string {
	var out []string
	for _, t := range sortedCopy(techniques) {
		id := strings.TrimSpace(t)
		if id == "" {
			continue
		}
		out = append(out, "attack."+strings.ToLower(id))
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func listOrNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(sortedCopy(in), ", ")
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
