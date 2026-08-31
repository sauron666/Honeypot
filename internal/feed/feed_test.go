package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
)

func sampleEngagement() engagement.Engagement {
	return engagement.Engagement{
		ID:         "eng_secret123",
		TenantID:   "acme-corp",
		SiteID:     "hq-datacenter",
		SrcIP:      "203.0.113.7",
		Techniques: []string{"T1110", "T1486"},
		Services:   []string{"ssh", "smb"},
		Phases: []engagement.Phase{
			engagement.PhaseRecon,
			engagement.PhaseAccess,
			engagement.PhaseImpact,
		},
		Authenticated:  true,
		MaxSeverity:    event.SeverityCritical,
		HoneytokensHit: []string{"aws-key-AKIASECRET"},
		Commands:       12,
		PayloadURLs:    []string{"http://evil.com/a/b?x=1"},
	}
}

func TestAnonymizeStripsIdentifiers(t *testing.T) {
	eng := sampleEngagement()
	e := Anonymize(eng, "deployment-salt-1")

	// TTPs are preserved.
	if strings.Join(e.Techniques, ",") != "T1110,T1486" {
		t.Fatalf("techniques not preserved: %v", e.Techniques)
	}
	if strings.Join(e.Services, ",") != "ssh,smb" {
		t.Fatalf("services not preserved: %v", e.Services)
	}
	if e.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", e.Severity)
	}
	if e.Phases != 3 {
		t.Fatalf("phases = %d, want 3", e.Phases)
	}
	if !e.Authenticated {
		t.Fatalf("authenticated not preserved")
	}

	// Nothing identifying may be recoverable from any field of the Entry.
	blob := marshalAllFields(e)
	for _, secret := range []string{
		eng.SrcIP, eng.TenantID, eng.SiteID, eng.ID,
		"aws-key-AKIASECRET", // honeytoken value
		"deployment-salt-1",  // the salt itself
		"/a/b", "x=1",        // path and query of the payload URL
	} {
		if strings.Contains(blob, secret) {
			t.Fatalf("entry leaked %q: %s", secret, blob)
		}
	}
}

func TestAnonymizePayloadDomains(t *testing.T) {
	eng := engagement.Engagement{
		PayloadURLs: []string{
			"http://evil.com/a/b?x=1",
			"https://user:pass@evil.com:8443/x", // dup host, with creds+port
			"https://second.example/path",
			"://not a url",      // malformed -> dropped
			"nohostscheme:blah", // no host -> dropped
		},
	}
	e := Anonymize(eng, "salt")

	got := strings.Join(e.PayloadDomains, ",")
	if got != "evil.com,second.example" {
		t.Fatalf("payload domains = %q, want evil.com,second.example", got)
	}
	// No path, query, creds, or port leaked.
	for _, bad := range []string{"/a/b", "x=1", "user", "pass", "8443", "/path"} {
		for _, d := range e.PayloadDomains {
			if strings.Contains(d, bad) {
				t.Fatalf("payload domain %q leaked %q", d, bad)
			}
		}
	}
}

func TestSourceHashProperties(t *testing.T) {
	a := Anonymize(sampleEngagement(), "salt-A")
	a2 := Anonymize(sampleEngagement(), "salt-A")
	b := Anonymize(sampleEngagement(), "salt-B")

	if a.SourceHash != a2.SourceHash {
		t.Fatalf("source hash not stable for the same salt: %s vs %s", a.SourceHash, a2.SourceHash)
	}
	if a.SourceHash == b.SourceHash {
		t.Fatalf("source hash collided across different salts")
	}
	if a.SourceHash == "salt-A" {
		t.Fatalf("source hash equals the salt (reversible)")
	}
	if len(a.SourceHash) != 12 {
		t.Fatalf("source hash length = %d, want 12", len(a.SourceHash))
	}
}

func TestEntryIDDoesNotEmbedEngagementID(t *testing.T) {
	eng := sampleEngagement()
	e := Anonymize(eng, "salt")
	if strings.Contains(e.ID, eng.ID) || strings.Contains(e.ID, "secret123") {
		t.Fatalf("entry id embeds engagement id: %s", e.ID)
	}
	// Two anonymizations of the same engagement get distinct ids.
	if e.ID == Anonymize(eng, "salt").ID {
		t.Fatalf("entry ids are not fresh")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &Feed{Version: 1, Entries: []Entry{Anonymize(sampleEngagement(), "salt")}}

	if err := f.Verify(pub); err != ErrUnsigned {
		t.Fatalf("unsigned feed: got %v, want ErrUnsigned", err)
	}
	if err := f.Sign(priv, "fp-1234"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := f.Verify(pub); err != nil {
		t.Fatalf("verify after sign: %v", err)
	}

	// Round-trip through Marshal/ParseFeed keeps the signature valid.
	raw, err := f.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseFeed(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(pub); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &Feed{Version: 1, Entries: []Entry{Anonymize(sampleEngagement(), "salt")}}
	if err := f.Sign(priv, "fp"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Mutate an entry after signing.
	f.Entries[0].Severity = "Low"
	if err := f.Verify(pub); err == nil {
		t.Fatalf("verify accepted a tampered feed")
	}
}

func TestMergeDedupsByID(t *testing.T) {
	e1 := Entry{ID: "a", Severity: "High"}
	e2 := Entry{ID: "b", Severity: "Low"}
	e3 := Entry{ID: "a", Severity: "Critical"} // same id as e1

	f := &Feed{Entries: []Entry{e1}}
	f.Merge(&Feed{Entries: []Entry{e2, e3}})

	if len(f.Entries) != 2 {
		t.Fatalf("merge produced %d entries, want 2: %+v", len(f.Entries), f.Entries)
	}
	ids := map[string]int{}
	for _, e := range f.Entries {
		ids[e.ID]++
	}
	if ids["a"] != 1 || ids["b"] != 1 {
		t.Fatalf("merge did not dedup by id: %v", ids)
	}
}

// marshalAllFields renders every field of an Entry to a single string so a test
// can assert no forbidden substring appears anywhere in it.
func marshalAllFields(e Entry) string {
	raw, err := (&Feed{Entries: []Entry{e}}).Marshal()
	if err != nil {
		return ""
	}
	return string(raw)
}
