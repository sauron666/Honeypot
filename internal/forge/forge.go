// Package forge turns an observed intrusion into detection content for the
// real network.
//
// This is the point of the whole platform. A decoy that only raises alerts
// tells you that something happened in a place that does not matter. A decoy
// that hands your SIEM a validated Sigma rule, your IDS a signature and your
// EDR a hash tells you what to look for where it does matter.
//
// The hard part is not generation, it is restraint. A rule built from "ls" or
// from a browser's user agent would fire constantly and get the whole feed
// switched off, so everything here is filtered through a specificity check and
// anything rejected is reported with its reason rather than silently dropped.
package forge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/version"
)

// Format identifies a detection format.
type Format string

const (
	FormatSigma    Format = "sigma"
	FormatSuricata Format = "suricata"
	FormatYARA     Format = "yara"
	FormatSTIX     Format = "stix"
	FormatReport   Format = "report"
)

// Rule is one generated detection.
type Rule struct {
	ID        string `json:"id"`
	Format    Format `json:"format"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Rationale string `json:"rationale"`
	// Technique is the ATT&CK id the rule detects, where there is one.
	Technique string `json:"technique,omitempty"`
}

// IOC is one indicator worth acting on.
type IOC struct {
	Type    string `json:"type"` // ipv4-addr, url, domain-name, file-hash, user-agent
	Value   string `json:"value"`
	Context string `json:"context"`
}

// Rejection records something the forge declined to turn into a rule, and why.
// Publishing these is deliberate: an operator should be able to see what was
// skipped and disagree.
type Rejection struct {
	Candidate string `json:"candidate"`
	Reason    string `json:"reason"`
}

// Bundle is everything the forge produced for one engagement.
type Bundle struct {
	EngagementID string      `json:"engagement_id"`
	GeneratedAt  time.Time   `json:"generated_at"`
	Rules        []Rule      `json:"rules"`
	IOCs         []IOC       `json:"iocs"`
	Rejected     []Rejection `json:"rejected"`
	Report       string      `json:"report"`
	STIX         string      `json:"stix"`
}

// RulesOf returns the rules of one format.
func (b *Bundle) RulesOf(f Format) []Rule {
	var out []Rule
	for _, r := range b.Rules {
		if r.Format == f {
			out = append(out, r)
		}
	}
	return out
}

// Forge builds detection content.
type Forge struct {
	// MinCommandLength rejects command lines too short to be distinctive.
	MinCommandLength int
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// New returns a forge with sensible thresholds.
func New() *Forge {
	return &Forge{MinCommandLength: 12, Now: time.Now}
}

// Build produces a bundle from an engagement and its events.
func (f *Forge) Build(eng *engagement.Engagement, events []*event.Event) *Bundle {
	b := &Bundle{
		EngagementID: eng.ID,
		GeneratedAt:  f.Now().UTC(),
	}

	seen := map[string]bool{}
	addRule := func(r Rule) {
		key := string(r.Format) + "|" + r.Title
		if seen[key] {
			return
		}
		seen[key] = true
		r.ID = ruleID(r.Format, r.Title)
		b.Rules = append(b.Rules, r)
	}
	reject := func(candidate, reason string) {
		if len(candidate) > 120 {
			candidate = candidate[:120] + "..."
		}
		b.Rejected = append(b.Rejected, Rejection{Candidate: candidate, Reason: reason})
	}

	f.commandRules(events, addRule, reject)
	f.webRules(events, addRule, reject)
	f.networkRules(eng, events, addRule, reject)
	f.payloadRules(events, addRule, reject)
	f.credentialRules(eng, events, addRule)

	b.IOCs = f.iocs(eng, events, reject)
	b.STIX = f.stix(eng, b)
	b.Report = f.report(eng, events, b)

	sort.SliceStable(b.Rules, func(i, j int) bool {
		if b.Rules[i].Format != b.Rules[j].Format {
			return b.Rules[i].Format < b.Rules[j].Format
		}
		return b.Rules[i].Title < b.Rules[j].Title
	})
	return b
}

// ubiquitous commands would match on every host in the estate every minute.
// Building a rule from one is how a detection feed gets muted.
var ubiquitous = map[string]bool{
	"ls": true, "cd": true, "pwd": true, "whoami": true, "id": true, "exit": true,
	"clear": true, "date": true, "uname": true, "hostname": true, "echo": true,
	"ps": true, "df": true, "free": true, "w": true, "who": true, "history": true,
	"uptime": true, "env": true, "top": true, "ll": true, "dir": true,
}

// distinctive marks command fragments that are worth a rule on their own.
var distinctive = []struct {
	needle    string
	technique string
	name      string
}{
	{"/etc/shadow", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"},
	{"id_rsa", "T1552.004", "Unsecured Credentials: Private Keys"},
	{"authorized_keys", "T1098.004", "Account Manipulation: SSH Authorized Keys"},
	{"history -c", "T1070.003", "Indicator Removal: Clear Command History"},
	{"vssadmin", "T1490", "Inhibit System Recovery"},
	{"wbadmin", "T1490", "Inhibit System Recovery"},
	{"bcdedit", "T1490", "Inhibit System Recovery"},
	{"xp_cmdshell", "T1059", "Command and Scripting Interpreter"},
	{"into outfile", "T1505", "Server Software Component"},
	{"load_file(", "T1005", "Data from Local System"},
	{"/dev/tcp/", "T1059.004", "Unix Shell"},
	{"base64 -d", "T1140", "Deobfuscate/Decode Files or Information"},
	{"chattr +i", "T1222", "File and Directory Permissions Modification"},
	{"crontab -", "T1053.003", "Scheduled Task/Job: Cron"},
	{"systemctl stop", "T1489", "Service Stop"},
	{"nohup ", "T1059.004", "Unix Shell"},
}

func (f *Forge) commandRules(events []*event.Event, add func(Rule), reject func(string, string)) {
	seenCmd := map[string]bool{}
	for _, e := range events {
		if e.ClassUID != event.ClassCommandExecuted {
			continue
		}
		cmd := strings.TrimSpace(e.GetString("command"))
		if cmd == "" || seenCmd[cmd] {
			continue
		}
		seenCmd[cmd] = true

		first := strings.Fields(cmd)
		if len(first) > 0 && ubiquitous[first[0]] && !hasDistinctive(cmd) {
			reject(cmd, "the command is ubiquitous; a rule would match normal administration everywhere")
			continue
		}
		if len(cmd) < f.MinCommandLength && !hasDistinctive(cmd) {
			reject(cmd, fmt.Sprintf("shorter than %d characters and carries no distinctive fragment",
				f.MinCommandLength))
			continue
		}

		needle, technique, name := bestFragment(cmd)
		if needle == "" {
			reject(cmd, "no fragment specific enough to survive contact with a real estate")
			continue
		}
		add(Rule{
			Format:    FormatSigma,
			Title:     "Suspicious command fragment: " + needle,
			Technique: technique,
			Rationale: fmt.Sprintf("observed on a decoy as part of %q; %s", truncate(cmd, 120), name),
			Content:   sigmaCommand(needle, name, technique, cmd),
		})
	}
}

func hasDistinctive(cmd string) bool {
	n, _, _ := bestFragment(cmd)
	return n != ""
}

// bestFragment picks the most specific known fragment in a command line.
func bestFragment(cmd string) (needle, technique, name string) {
	l := strings.ToLower(cmd)
	for _, d := range distinctive {
		if strings.Contains(l, d.needle) {
			return d.needle, d.technique, d.name
		}
	}
	// Fall back to a downloader with a URL, which is always worth a rule.
	if m := urlRe.FindString(cmd); m != "" {
		return m, "T1105", "Ingress Tool Transfer"
	}
	return "", "", ""
}

var urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s'"|;)]+`)

func (f *Forge) webRules(events []*event.Event, add func(Rule), reject func(string, string)) {
	seenPath := map[string]bool{}
	for _, e := range events {
		if e.Mirage.Service != "http" && e.Mirage.Service != "tokens" {
			continue
		}
		path := e.GetString("url_path")
		findings, _ := e.Get("findings")
		list, _ := findings.([]string)
		if len(list) == 0 || path == "" || seenPath[path] {
			continue
		}
		seenPath[path] = true

		if path == "/" || len(path) < 4 {
			reject(path, "the path is too common to signature")
			continue
		}
		add(Rule{
			Format:    FormatSuricata,
			Title:     "Web probe for " + path,
			Technique: "T1595.003",
			Rationale: fmt.Sprintf("requested on a decoy; findings: %s", strings.Join(list, ", ")),
			Content:   suricataHTTPPath(path, list),
		})
	}

	// Distinctive user agents are worth a rule; browser strings are not.
	seenUA := map[string]bool{}
	for _, e := range events {
		ua := e.GetString("user_agent")
		if ua == "" || seenUA[ua] {
			continue
		}
		seenUA[ua] = true
		if looksLikeBrowser(ua) {
			reject(ua, "the user agent is a normal browser string")
			continue
		}
		add(Rule{
			Format:    FormatSuricata,
			Title:     "Tool user agent: " + truncate(ua, 60),
			Technique: "T1071.001",
			Rationale: "sent to a decoy; distinctive enough to identify the tool",
			Content:   suricataUserAgent(ua),
		})
	}
}

func looksLikeBrowser(ua string) bool {
	l := strings.ToLower(ua)
	if strings.Contains(l, "${") || strings.Contains(l, "jndi") {
		return false // an exploit hidden in a browser-shaped string
	}
	return strings.Contains(l, "mozilla/") || strings.Contains(l, "chrome/") ||
		strings.Contains(l, "safari/") || strings.Contains(l, "firefox/")
}

func (f *Forge) networkRules(eng *engagement.Engagement, events []*event.Event,
	add func(Rule), reject func(string, string)) {

	for _, u := range eng.PayloadURLs {
		add(Rule{
			Format:    FormatSuricata,
			Title:     "Second-stage payload URL: " + truncate(u, 60),
			Technique: "T1105",
			Rationale: "an attacker on a decoy referenced this URL; any host fetching it is compromised",
			Content:   suricataURL(u),
		})
	}

	// Redis takeover is distinctive enough on the wire to signature directly.
	for _, e := range events {
		if e.Mirage.Service == "redis" && e.GetString("config_key") == "dir" {
			add(Rule{
				Format:    FormatSuricata,
				Title:     "Redis CONFIG SET dir (takeover chain)",
				Technique: "T1059",
				Rationale: "observed on a decoy; no application changes the Redis dump directory at runtime",
				Content:   suricataRedisConfig(),
			})
		}
	}
}

func (f *Forge) payloadRules(events []*event.Event, add func(Rule), reject func(string, string)) {
	for _, e := range events {
		hash := e.GetString("sha256")
		preview := e.GetString("payload_preview")
		if hash == "" {
			continue
		}
		kind := e.GetString("payload_kind")
		strs := yaraStrings(preview)
		if len(strs) < 2 {
			reject(hash, "the captured payload has too few distinctive strings for a YARA rule")
			continue
		}
		add(Rule{
			Format:    FormatYARA,
			Title:     "Captured payload " + hash[:12],
			Technique: "T1105",
			Rationale: fmt.Sprintf("uploaded to a decoy (%s, sha256 %s)", kind, hash),
			Content:   yaraRule(hash, kind, strs),
		})
	}
}

func (f *Forge) credentialRules(eng *engagement.Engagement, events []*event.Event, add func(Rule)) {
	users := map[string]bool{}
	for _, e := range events {
		if e.ClassUID != event.ClassCredentialOffer {
			continue
		}
		if u := e.GetString("username"); u != "" {
			users[u] = true
		}
	}
	if len(users) == 0 {
		return
	}
	list := make([]string, 0, len(users))
	for u := range users {
		list = append(list, u)
	}
	sort.Strings(list)

	add(Rule{
		Format:    FormatSigma,
		Title:     "Authentication attempts for accounts targeted on a decoy",
		Technique: "T1110",
		Rationale: fmt.Sprintf("these %d account names were tried against a decoy; "+
			"the same names appearing in production authentication logs are the same campaign", len(list)),
		Content: sigmaTargetedAccounts(list, eng.SrcIP),
	})
}

func (f *Forge) iocs(eng *engagement.Engagement, events []*event.Event, reject func(string, string)) []IOC {
	var out []IOC
	seen := map[string]bool{}
	addIOC := func(typ, value, context string) {
		key := typ + "|" + value
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, IOC{Type: typ, Value: value, Context: context})
	}

	addIOC("ipv4-addr", eng.SrcIP, "source of the engagement")
	for _, u := range eng.PayloadURLs {
		addIOC("url", u, "second-stage payload referenced on a decoy")
	}
	for _, e := range events {
		if h := e.GetString("sha256"); h != "" {
			addIOC("file-hash-sha256", h, "payload captured by a decoy ("+e.GetString("payload_kind")+")")
		}
		if ua := e.GetString("user_agent"); ua != "" && !looksLikeBrowser(ua) {
			addIOC("user-agent", ua, "tool fingerprint")
		}
		if fp := e.GetString("key_fingerprint"); fp != "" {
			addIOC("ssh-key-fingerprint", fp, "public key offered to a decoy; durable across IP changes")
		}
		if tool := e.GetString("client_tool"); tool != "" && tool != "unknown" {
			addIOC("tool", tool, "client software identified from the protocol handshake")
		}
	}
	return out
}

func ruleID(f Format, title string) string {
	sum := sha256.Sum256([]byte(string(f) + "|" + title))
	return hex.EncodeToString(sum[:8])
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// generatedBy is the provenance line every artifact carries, so that nobody has
// to guess where a rule in their SIEM came from.
func generatedBy(engID string) string {
	return fmt.Sprintf("%s %s from decoy engagement %s", version.Product, version.Version, engID)
}
