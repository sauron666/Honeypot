// Package toolkit fingerprints attacker tools from their network behaviour.
//
// Every tool leaves a signature — not in what it says, but in how it says it:
// the order of operations, the timing, the options it chooses. nmap's SYN scan
// sends probes in a characteristic order and timing; Impacket's smbexec speaks
// DCERPC in a way smbclient does not; Rubeus asks for RC4 first when a real
// Windows client asks for AES. These patterns identify the tool itself, and
// often its version, which is more useful than the IP behind it: the IP rotates,
// the tool choice fingerprints the actor.
//
// The database here is a set of rules that match against the attributes an
// engagement has accumulated. When enough attributes match a signature, the
// tool is identified and the engagement is annotated. A future step
// (docs/11-IDEAS.md #8) uses the identification to predict the next action.
package toolkit

import (
	"sort"
	"strings"
)

// Signature describes one tool or tool family.
type Signature struct {
	// Name is what the analyst reads: "Impacket", "nmap", "Rubeus", etc.
	Name string `json:"name"`
	// Version narrows when the signal distinguishes it, e.g. "0.11.x".
	Version string `json:"version,omitempty"`
	// Family groups related tools: "Impacket", "CobaltStrike", "Sliver", etc.
	Family string `json:"family,omitempty"`
	// Category is what the tool does: "scanner", "credential-access",
	// "lateral-movement", "c2", "post-exploitation".
	Category string `json:"category"`
	// Indicators are the attributes the engagement must have for a match. Each
	// is a key=value pair that is matched against the engagement's accumulated
	// attributes. All must match for the signature to fire.
	Indicators []string `json:"indicators"`
	// MinEvents is the minimum number of events before the signature is
	// considered. Tools that fire on a single event are usually wrong.
	MinEvents int `json:"min_events"`
	// Confidence is how sure the match is: "high" (unique signal), "medium"
	// (shared with a few tools), "low" (could be many things).
	Confidence string `json:"confidence"`
	// NextLikely is the ATT&CK technique the attacker most often runs next
	// after this tool has been identified. It is what makes the prediction:
	// "this is Impacket, so the next thing is probably secretsdump."
	NextLikely string `json:"next_likely,omitempty"`
	// Countermeasure is what to do about it.
	Countermeasure string `json:"countermeasure,omitempty"`
}

// Match is a confirmed tool identification.
type Match struct {
	Tool       Signature `json:"tool"`
	Confidence string    `json:"confidence"`
	MatchedOn  []string  `json:"matched_on"`
}

// DB is the tool fingerprint database.
type DB struct {
	sigs []Signature
}

// New builds a database from the built-in signatures.
func New() *DB {
	return &DB{sigs: builtinSignatures()}
}

// Identify checks an engagement's attributes against every signature and
// returns the matches, best-confidence first.
func (db *DB) Identify(attrs map[string]string, eventCount int) []Match {
	var matches []Match
	for _, sig := range db.sigs {
		if eventCount < sig.MinEvents {
			continue
		}
		var matched []string
		hit := true
		for _, ind := range sig.Indicators {
			parts := strings.SplitN(ind, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key, want := parts[0], parts[1]
			got, ok := attrs[key]
			if !ok {
				hit = false
				break
			}
			if want == "*" {
				matched = append(matched, ind)
				continue
			}
			if strings.EqualFold(got, want) || strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
				matched = append(matched, ind)
			} else {
				hit = false
				break
			}
		}
		if hit && len(matched) > 0 {
			matches = append(matches, Match{Tool: sig, Confidence: sig.Confidence, MatchedOn: matched})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return confRank(matches[i].Confidence) > confRank(matches[j].Confidence)
	})
	return matches
}

func confRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Signatures returns the full database for display.
func (db *DB) Signatures() []Signature { return append([]Signature(nil), db.sigs...) }

// builtinSignatures is the initial set. Each is written from public knowledge
// of how the tool behaves on the wire — the same way a SOC analyst recognises
// them, but encoded so it happens automatically.
func builtinSignatures() []Signature {
	return []Signature{
		{
			Name: "nmap", Family: "nmap", Category: "scanner",
			Indicators: []string{"technique=T1046"},
			MinEvents:  3, Confidence: "medium",
			NextLikely:     "T1110 (credential brute-force) or T1021 (remote services)",
			Countermeasure: "the scan itself is the detection; the decoy is already the response",
		},
		{
			Name: "Impacket secretsdump", Family: "Impacket", Category: "credential-access",
			Indicators: []string{"technique=T1003", "service=smb"},
			MinEvents:  2, Confidence: "high",
			NextLikely:     "T1021.002 (SMB/Windows Admin Shares) — pass-the-hash lateral movement",
			Countermeasure: "the NetNTLMv2 hash is already captured; watch for the same hash elsewhere",
		},
		{
			Name: "Impacket smbexec", Family: "Impacket", Category: "lateral-movement",
			Indicators: []string{"technique=T1021.002", "service=smb", "authenticated=true"},
			MinEvents:  3, Confidence: "high",
			NextLikely:     "T1059.001 (PowerShell) — command execution on the target",
			Countermeasure: "the session is already inside a decoy; every command is recorded",
		},
		{
			Name: "Rubeus", Family: "Rubeus", Category: "credential-access",
			Indicators: []string{"technique=T1558.003", "etype=23"},
			MinEvents:  1, Confidence: "high",
			NextLikely:     "T1550.002 (Pass the Ticket) — use the cracked ticket for lateral movement",
			Countermeasure: "the cracked credential is a planted password; watch for reuse",
		},
		{
			Name: "kerbrute", Family: "kerbrute", Category: "credential-access",
			Indicators: []string{"technique=T1087.002", "service=kerberos"},
			MinEvents:  5, Confidence: "medium",
			NextLikely:     "T1558.004 (AS-REP Roasting) or T1110.003 (Password Spraying)",
			Countermeasure: "the username list is the attacker's wordlist; it identifies their target set",
		},
		{
			Name: "BloodHound / SharpHound", Family: "BloodHound", Category: "reconnaissance",
			Indicators: []string{"technique=T1087.002", "service=ldap"},
			MinEvents:  5, Confidence: "medium",
			NextLikely:     "T1558.003 (Kerberoasting) — the attack path ends at a kerberoastable account",
			Countermeasure: "the directory is a decoy; every query is recorded and the paths lead nowhere",
		},
		{
			Name: "CobaltStrike Beacon", Family: "CobaltStrike", Category: "c2",
			Indicators: []string{"technique=T1059", "authenticated=true"},
			MinEvents:  3, Confidence: "low",
			NextLikely:     "T1003 (Credential Dumping) or T1055 (Process Injection)",
			Countermeasure: "beacon traffic is recorded; extract the C2 profile from the session transcript",
		},
		{
			Name: "Metasploit", Family: "Metasploit", Category: "post-exploitation",
			Indicators: []string{"technique=T1059", "payload_url=*"},
			MinEvents:  2, Confidence: "medium",
			NextLikely:     "T1105 (Ingress Tool Transfer) — second-stage payload download",
			Countermeasure: "the payload URL is recorded; block it on the perimeter and check the real estate",
		},
		{
			Name: "Hydra / Medusa", Family: "brute-forcer", Category: "credential-access",
			Indicators: []string{"technique=T1110", "credentials_offered>10"},
			MinEvents:  10, Confidence: "medium",
			NextLikely:     "T1021 (Remote Services) — use the found credential",
			Countermeasure: "the planted credential will be found; watch for reuse across the deployment",
		},
		{
			Name: "Mimikatz / lsassy", Family: "Mimikatz", Category: "credential-access",
			Indicators: []string{"technique=T1003.001"},
			MinEvents:  1, Confidence: "high",
			NextLikely:     "T1550 (Use Alternate Authentication Material) — pass-the-hash/ticket",
			Countermeasure: "inside a decoy VM, the credential is planted; outside, alert immediately",
		},
		{
			Name: "GetNPUsers (AS-REP roast)", Family: "Impacket", Category: "credential-access",
			Indicators: []string{"technique=T1558.004", "service=kerberos"},
			MinEvents:  1, Confidence: "high",
			NextLikely:     "offline cracking → T1078 (Valid Accounts) — use the cracked password",
			Countermeasure: "the cracked password is planted and watched everywhere",
		},
		{
			Name: "ransomware encryptor", Family: "ransomware", Category: "impact",
			Indicators: []string{"technique=T1486"},
			MinEvents:  3, Confidence: "medium",
			NextLikely:     "T1490 (Inhibit System Recovery) — shadow copy deletion",
			Countermeasure: "tarpit the session; the canary files fire first, buying time",
		},
	}
}
