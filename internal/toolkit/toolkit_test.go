package toolkit

import (
	"testing"
)

func TestIdentifiesRubeusFromKerberoast(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique": "T1558.003",
		"etype":     "23",
		"service":   "kerberos",
	}, 2)
	if len(matches) == 0 {
		t.Fatal("Rubeus kerberoast was not identified")
	}
	if matches[0].Tool.Name != "Rubeus" {
		t.Fatalf("expected Rubeus, got %s", matches[0].Tool.Name)
	}
	if matches[0].Tool.NextLikely == "" {
		t.Fatal("no prediction for what comes next")
	}
}

func TestIdentifiesASREPRoast(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique": "T1558.004",
		"service":   "kerberos",
	}, 1)
	if len(matches) == 0 {
		t.Fatal("AS-REP roast not identified")
	}
	if !containsTool(matches, "GetNPUsers (AS-REP roast)") {
		t.Fatalf("expected GetNPUsers, got %v", toolNames(matches))
	}
}

func TestIdentifiesRansomware(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique": "T1486",
	}, 5)
	if len(matches) == 0 {
		t.Fatal("ransomware not identified")
	}
	if !containsTool(matches, "ransomware encryptor") {
		t.Fatalf("expected ransomware, got %v", toolNames(matches))
	}
}

func TestDoesNotMatchOnTooFewEvents(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique":           "T1110",
		"credentials_offered": "50",
	}, 1) // Hydra needs MinEvents=10
	for _, m := range matches {
		if m.Tool.Name == "Hydra / Medusa" {
			t.Fatal("Hydra matched on too few events")
		}
	}
}

func TestMatchesAreSortedByConfidence(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique": "T1087.002",
		"service":   "ldap",
	}, 10)
	if len(matches) < 1 {
		t.Fatal("no matches for LDAP enumeration")
	}
	for i := 1; i < len(matches); i++ {
		if confRank(matches[i].Confidence) > confRank(matches[i-1].Confidence) {
			t.Fatalf("matches not sorted by confidence: %s > %s",
				matches[i].Confidence, matches[i-1].Confidence)
		}
	}
}

func TestDatabaseIsNotEmpty(t *testing.T) {
	db := New()
	if len(db.Signatures()) < 10 {
		t.Fatalf("expected at least 10 signatures, got %d", len(db.Signatures()))
	}
	for _, sig := range db.Signatures() {
		if sig.Name == "" || sig.Category == "" || len(sig.Indicators) == 0 {
			t.Fatalf("incomplete signature: %+v", sig)
		}
	}
}

func TestWildcardIndicatorMatches(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique":   "T1059",
		"payload_url": "http://evil.com/shell.exe",
	}, 5)
	if !containsTool(matches, "Metasploit") {
		t.Fatalf("Metasploit not identified with wildcard payload_url, got %v", toolNames(matches))
	}
}

func TestNoMatchReturnsEmpty(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{"technique": "T9999"}, 100)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for unknown technique, got %v", toolNames(matches))
	}
}

func TestSignaturesReturnsDefensiveCopy(t *testing.T) {
	db := New()
	a := db.Signatures()
	origLen := len(a)
	a = append(a, Signature{Name: "evil"})
	b := db.Signatures()
	if len(b) != origLen {
		t.Fatalf("mutating returned slice affected DB: len went from %d to %d", origLen, len(b))
	}
}

func TestCaseInsensitiveMatch(t *testing.T) {
	db := New()
	matches := db.Identify(map[string]string{
		"technique": "t1558.003",
		"etype":     "23",
	}, 2)
	if !containsTool(matches, "Rubeus") {
		t.Fatalf("case-insensitive match failed, got %v", toolNames(matches))
	}
}

func containsTool(matches []Match, name string) bool {
	for _, m := range matches {
		if m.Tool.Name == name {
			return true
		}
	}
	return false
}

func toolNames(matches []Match) []string {
	var out []string
	for _, m := range matches {
		out = append(out, m.Tool.Name)
	}
	return out
}
