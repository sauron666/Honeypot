package forge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
)

// --- Sigma ------------------------------------------------------------------

func sigmaCommand(needle, name, technique, observed string) string {
	return fmt.Sprintf(`title: Suspicious command containing %s
id: %s
status: experimental
description: |
  Detects a command line containing %q, observed on a MIRAGE decoy during a real
  intrusion. On a decoy this string has no legitimate cause; validate against
  your own baseline before enabling in blocking mode.
references:
  - internal MIRAGE decoy engagement
author: MIRAGE
date: %s
tags:
  - attack.%s
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: %s
  condition: selection
falsepositives:
  - administrative scripts that legitimately touch this path
level: high
`, needle, sigmaUUID(needle+technique), needle, time.Now().UTC().Format("2006/01/02"),
		strings.ToLower(technique), sigmaScalar(needle))
}

func sigmaTargetedAccounts(users []string, srcIP string) string {
	var items strings.Builder
	for _, u := range users {
		items.WriteString("      - " + sigmaScalar(u) + "\n")
	}
	return fmt.Sprintf(`title: Authentication attempts for accounts targeted on a decoy
id: %s
status: experimental
description: |
  These account names were tried against a MIRAGE decoy from %s. The same names
  appearing in production authentication logs indicate the same campaign
  reaching real systems.
author: MIRAGE
date: %s
tags:
  - attack.t1110
logsource:
  category: authentication
detection:
  selection:
    TargetUserName:
%s  condition: selection
falsepositives:
  - service accounts that share a name with a guessed one
level: medium
`, sigmaUUID(strings.Join(users, ",")), srcIP, time.Now().UTC().Format("2006/01/02"), items.String())
}

// sigmaScalar renders a YAML scalar safely, quoting when needed.
func sigmaScalar(s string) string {
	if s == "" {
		return `''`
	}
	needsQuote := strings.ContainsAny(s, ":#{}[],&*?|-<>=!%@`\"'\n\\ ") ||
		strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ")
	if !needsQuote {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sigmaUUID derives a stable UUID-shaped id, so regenerating a rule for the
// same observation does not create a duplicate in the SIEM.
func sigmaUUID(seed string) string {
	sum := sha256.Sum256([]byte("mirage-uuid|" + seed))
	h := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// --- Suricata ---------------------------------------------------------------

// sidFor derives a deterministic signature id in the local range reserved for
// site-specific rules.
func sidFor(seed string) int {
	h := ruleID(FormatSuricata, seed)
	var n int
	for i := 0; i < 8 && i < len(h); i++ {
		n = n*16 + hexVal(h[i])
	}
	if n < 0 {
		n = -n
	}
	return 1000000 + n%899999
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return 0
	}
}

// suricataContent renders a content match, falling back to hex for anything
// that is not safely printable inside a rule.
func suricataContent(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == ';' || c == '\\' || c == '|' {
			safe = false
			break
		}
	}
	if safe {
		return `"` + s + `"`
	}
	// Mixed form: hex-encode everything, which is always valid.
	var b strings.Builder
	b.WriteString(`"|`)
	for i := 0; i < len(s); i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(hex.EncodeToString([]byte{s[i]}))
	}
	b.WriteString(`|"`)
	return b.String()
}

func suricataHTTPPath(path string, findings []string) string {
	return fmt.Sprintf(`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MIRAGE observed probe for %s"; `+
		`flow:established,to_server; http.uri; content:%s; nocase; `+
		`classtype:web-application-attack; metadata:mirage_finding %s; sid:%d; rev:1;)`,
		suricataMsg(path), suricataContent(path),
		suricataMetadata(strings.Join(findings, "-")), sidFor("path:"+path))
}

func suricataUserAgent(ua string) string {
	return fmt.Sprintf(`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"MIRAGE observed tool user agent %s"; `+
		`flow:established,to_server; http.user_agent; content:%s; `+
		`classtype:attempted-recon; sid:%d; rev:1;)`,
		suricataMsg(truncate(ua, 60)), suricataContent(ua), sidFor("ua:"+ua))
}

func suricataURL(u string) string {
	host, path := splitURL(u)
	rule := fmt.Sprintf(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MIRAGE second-stage payload URL seen on a decoy: %s"; `+
		`flow:established,to_server; http.host; content:%s;`, suricataMsg(truncate(u, 60)), suricataContent(host))
	if path != "" && path != "/" {
		rule += fmt.Sprintf(` http.uri; content:%s;`, suricataContent(path))
	}
	rule += fmt.Sprintf(` classtype:trojan-activity; sid:%d; rev:1;)`, sidFor("url:"+u))
	return rule
}

func suricataRedisConfig() string {
	return fmt.Sprintf(`alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (msg:"MIRAGE Redis CONFIG SET dir (takeover chain)"; `+
		`flow:established,to_server; content:"CONFIG"; nocase; content:"SET"; nocase; distance:0; `+
		`content:"dir"; nocase; distance:0; classtype:attempted-admin; sid:%d; rev:1;)`,
		sidFor("redis-config-dir"))
}

// suricataMetadata renders a metadata value: Suricata parses these as
// whitespace-separated key/value pairs, so anything that could be read as a
// separator has to go.
func suricataMetadata(s string) string {
	r := strings.NewReplacer(":", "-", ",", "-", ";", "-", " ", "_", `"`, "", "\\", "-")
	return truncate(r.Replace(s), 60)
}

// suricataMsg strips characters that would terminate a rule option.
func suricataMsg(s string) string {
	r := strings.NewReplacer(`"`, "'", ";", ",", "\\", "/", "\n", " ", "\r", "")
	return truncate(r.Replace(s), 120)
}

func splitURL(u string) (host, path string) {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.Index(trimmed, "/"); i >= 0 {
		return trimmed[:i], trimmed[i:]
	}
	return trimmed, ""
}

// --- YARA -------------------------------------------------------------------

// yaraStrings picks distinctive printable runs out of a captured payload.
//
// Previews arrive with unprintable bytes already rendered as dots, so a run of
// two or more dots is a boundary between real strings; without that, a whole
// preview reads as one enormous "string" and nothing usable comes out.
func yaraStrings(preview string) []string {
	var (
		out  []string
		cur  strings.Builder
		seen = map[string]bool{}
		dots int
	)
	flush := func() {
		s := strings.Trim(strings.TrimSpace(cur.String()), ".")
		cur.Reset()
		dots = 0
		if len(s) < 8 || len(s) > 80 || seen[s] {
			return
		}
		// Skip runs that are only punctuation or padding.
		letters := 0
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				letters++
			}
		}
		if letters < 5 {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, c := range preview {
		switch {
		case c == '.':
			dots++
			if dots >= 2 {
				flush()
				continue
			}
			cur.WriteRune(c)
		case c >= 0x20 && c < 0x7f && c != '"' && c != '\\':
			dots = 0
			cur.WriteRune(c)
		default:
			dots = 0
			flush()
		}
	}
	flush()
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func yaraRule(hash, kind string, strs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule MIRAGE_captured_%s\n{\n    meta:\n", hash[:12])
	fmt.Fprintf(&b, "        description = \"payload captured by a MIRAGE decoy (%s)\"\n", kind)
	fmt.Fprintf(&b, "        sha256 = \"%s\"\n", hash)
	fmt.Fprintf(&b, "        author = \"MIRAGE\"\n        date = \"%s\"\n",
		time.Now().UTC().Format("2006-01-02"))
	b.WriteString("    strings:\n")
	for i, s := range strs {
		fmt.Fprintf(&b, "        $s%d = \"%s\" ascii\n", i, s)
	}
	// Requiring a majority of the strings keeps the rule from firing on a
	// single common substring.
	need := (len(strs) / 2) + 1
	fmt.Fprintf(&b, "    condition:\n        %d of them\n}\n", need)
	return b.String()
}

// --- STIX 2.1 ---------------------------------------------------------------

type stixObject map[string]any

func (f *Forge) stix(eng *engagement.Engagement, b *Bundle) string {
	now := f.Now().UTC().Format(time.RFC3339)
	objects := []stixObject{{
		"type":           "identity",
		"spec_version":   "2.1",
		"id":             "identity--" + sigmaUUID("mirage-identity"),
		"created":        now,
		"modified":       now,
		"name":           "MIRAGE deception platform",
		"identity_class": "system",
	}}

	for _, ioc := range b.IOCs {
		pattern, ok := stixPattern(ioc)
		if !ok {
			continue
		}
		objects = append(objects, stixObject{
			"type":            "indicator",
			"spec_version":    "2.1",
			"id":              "indicator--" + sigmaUUID(ioc.Type+ioc.Value),
			"created":         now,
			"modified":        now,
			"name":            fmt.Sprintf("%s observed on a decoy", ioc.Type),
			"description":     ioc.Context + " (" + generatedBy(eng.ID) + ")",
			"indicator_types": []string{"malicious-activity"},
			"pattern":         pattern,
			"pattern_type":    "stix",
			"valid_from":      now,
			"confidence":      85,
			"labels":          []string{"mirage", "deception", "high-confidence"},
		})
	}

	for _, technique := range eng.Techniques {
		objects = append(objects, stixObject{
			"type":         "attack-pattern",
			"spec_version": "2.1",
			"id":           "attack-pattern--" + sigmaUUID("attack:"+technique),
			"created":      now,
			"modified":     now,
			"name":         technique,
			"external_references": []stixObject{{
				"source_name": "mitre-attack",
				"external_id": technique,
				"url":         "https://attack.mitre.org/techniques/" + strings.ReplaceAll(technique, ".", "/"),
			}},
		})
	}

	bundle := stixObject{
		"type":    "bundle",
		"id":      "bundle--" + sigmaUUID("bundle:"+eng.ID),
		"objects": objects,
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func stixPattern(ioc IOC) (string, bool) {
	esc := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
	}
	switch ioc.Type {
	case "ipv4-addr":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", esc(ioc.Value)), true
	case "url":
		return fmt.Sprintf("[url:value = '%s']", esc(ioc.Value)), true
	case "file-hash-sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", esc(ioc.Value)), true
	case "user-agent":
		return fmt.Sprintf("[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '%s']",
			esc(ioc.Value)), true
	default:
		// Tool names and key fingerprints have no standard STIX pattern; they
		// stay in the IOC list rather than becoming a malformed indicator.
		return "", false
	}
}

// --- Report -----------------------------------------------------------------

func (f *Forge) report(eng *engagement.Engagement, events []*event.Event, b *Bundle) string {
	var w strings.Builder

	fmt.Fprintf(&w, "# Incident report: engagement %s\n\n", eng.ID)
	fmt.Fprintf(&w, "*Generated by %s*\n\n", generatedBy(eng.ID))

	fmt.Fprintf(&w, "## Summary\n\n%s.\n\n", capitalise(eng.Summary))
	fmt.Fprintf(&w, "| | |\n|---|---|\n")
	fmt.Fprintf(&w, "| Source | `%s` |\n", eng.SrcIP)
	fmt.Fprintf(&w, "| Started | %s |\n", eng.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&w, "| Last seen | %s |\n", eng.LastSeen.UTC().Format(time.RFC3339))
	fmt.Fprintf(&w, "| Duration | %s |\n", eng.LastSeen.Sub(eng.StartedAt).Round(time.Second))
	fmt.Fprintf(&w, "| Risk score | **%d/100** |\n", eng.RiskScore)
	fmt.Fprintf(&w, "| Authenticated | %v |\n", eng.Authenticated)
	fmt.Fprintf(&w, "| Decoys touched | %s |\n", strings.Join(eng.Decoys, ", "))
	fmt.Fprintf(&w, "| Services | %s |\n", strings.Join(eng.Services, ", "))
	fmt.Fprintf(&w, "| Events | %d |\n\n", eng.Events)

	if len(eng.Techniques) > 0 {
		w.WriteString("## Techniques observed\n\n")
		sorted := append([]string(nil), eng.Techniques...)
		sort.Strings(sorted)
		for _, t := range sorted {
			fmt.Fprintf(&w, "- `%s`\n", t)
		}
		w.WriteString("\n")
	}

	w.WriteString("## Timeline\n\n")
	shown := 0
	for _, e := range events {
		if e.SeverityID < event.SeverityMedium || shown >= 60 {
			continue
		}
		fmt.Fprintf(&w, "- `%s` **%s** %s\n",
			e.Timestamp().UTC().Format("15:04:05"), e.SeverityID, truncate(e.Message, 160))
		shown++
	}
	if shown == 0 {
		w.WriteString("_No events above informational severity._\n")
	}
	w.WriteString("\n")

	if len(eng.HoneytokensHit) > 0 {
		w.WriteString("## Honeytokens taken\n\n")
		for _, t := range eng.HoneytokensHit {
			fmt.Fprintf(&w, "- `%s`\n", t)
		}
		w.WriteString("\nEach of these is bait. If any appears in production telemetry, " +
			"the same actor has reached a real system.\n\n")
	}

	w.WriteString("## Indicators\n\n")
	if len(b.IOCs) == 0 {
		w.WriteString("_None extracted._\n\n")
	} else {
		w.WriteString("| Type | Value | Context |\n|---|---|---|\n")
		for _, i := range b.IOCs {
			fmt.Fprintf(&w, "| %s | `%s` | %s |\n", i.Type, truncate(i.Value, 80), i.Context)
		}
		w.WriteString("\n")
	}

	fmt.Fprintf(&w, "## Detection content generated\n\n%d rule(s):\n\n", len(b.Rules))
	for _, r := range b.Rules {
		fmt.Fprintf(&w, "- **%s** (%s) — %s\n", r.Title, r.Format, r.Rationale)
	}
	w.WriteString("\n")

	if len(b.Rejected) > 0 {
		w.WriteString("## Deliberately not turned into rules\n\n")
		w.WriteString("A rule that fires on normal activity gets the whole feed switched off, " +
			"so these candidates were rejected:\n\n")
		for _, r := range b.Rejected {
			fmt.Fprintf(&w, "- `%s` — %s\n", truncate(r.Candidate, 90), r.Reason)
		}
		w.WriteString("\n")
	}

	w.WriteString("## Next steps\n\n")
	w.WriteString("1. Load the Sigma rules into your SIEM and check them against the last 90 days.\n")
	w.WriteString("2. Load the Suricata rules on the perimeter and on the segment this decoy sits in.\n")
	w.WriteString("3. Block the file hashes in your EDR.\n")
	w.WriteString("4. Hunt for the honeytoken values above in production; a hit means a real system was reached.\n")
	if eng.Authenticated {
		w.WriteString("5. The attacker authenticated to a decoy. Check whether the credentials they used " +
			"exist on real systems and rotate them.\n")
	}
	return w.String()
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
