package insider

import (
	"strings"
	"testing"
)

func TestLuresAreVerticalSpecific(t *testing.T) {
	// A healthcare decoy full of trading-desk bait is not convincing. The kit
	// must tailor the lures to the vertical.
	health := NewKit("healthcare", "clinic.local").GenerateLures()
	finance := NewKit("finance", "bank.local").GenerateLures()

	joinNames := func(ls []Lure) string {
		var b strings.Builder
		for _, l := range ls {
			b.WriteString(l.Name + "\n")
		}
		return b.String()
	}
	hn, fn := joinNames(health), joinNames(finance)
	if !strings.Contains(hn, "Patient") {
		t.Fatalf("healthcare lures lack patient bait:\n%s", hn)
	}
	if !strings.Contains(fn, "Trading") && !strings.Contains(fn, "AML") {
		t.Fatalf("finance lures lack finance bait:\n%s", fn)
	}
	if hn == fn {
		t.Fatal("two verticals produced identical lures")
	}
}

func TestBaseLuresAlwaysPresent(t *testing.T) {
	// Every vertical gets the universally tempting bait too.
	lures := NewKit("generic", "corp.local").GenerateLures()
	if len(lures) == 0 {
		t.Fatal("no lures generated")
	}
	var haveDoc bool
	for _, l := range lures {
		if l.Type == "document" || l.Type == "share-folder" || l.Type == "database-record" {
			haveDoc = true
		}
		if l.Name == "" {
			t.Fatal("a lure has no name")
		}
	}
	if !haveDoc {
		t.Fatal("no recognisable lure type produced")
	}
}

func TestDPIAAndPolicyTemplatesNameTheOrg(t *testing.T) {
	// The compliance templates are what make an insider-threat deployment
	// legally defensible; they must be fillable, not generic boilerplate.
	dpia := DPIATemplate("Acme Ltd", "dpo@acme.example")
	if !strings.Contains(dpia, "Acme Ltd") || !strings.Contains(dpia, "dpo@acme.example") {
		t.Fatal("the DPIA template did not incorporate the org details")
	}
	pol := PolicyTemplate("Acme Ltd")
	if !strings.Contains(pol, "Acme Ltd") {
		t.Fatal("the policy template did not incorporate the org name")
	}
}

func TestAllVerticalsProduceDistinctLures(t *testing.T) {
	verticals := []string{"healthcare", "finance", "legal", "technology", "generic"}
	seen := map[string]string{}
	for _, v := range verticals {
		lures := NewKit(v, "corp.local").GenerateLures()
		if len(lures) == 0 {
			t.Fatalf("vertical %q produced no lures", v)
		}
		names := ""
		for _, l := range lures {
			names += l.Name + "|"
		}
		for other, otherNames := range seen {
			if names == otherNames && v != "generic" && other != "generic" {
				t.Fatalf("verticals %q and %q produced identical lure sets", v, other)
			}
		}
		seen[v] = names
	}
}

func TestLureNamesAreFilesystemSafe(t *testing.T) {
	for _, v := range []string{"healthcare", "finance", "legal", "technology", "generic"} {
		for _, l := range NewKit(v, "corp.local").GenerateLures() {
			if l.Name == "" {
				t.Fatalf("vertical %q produced a lure with empty name", v)
			}
			for _, bad := range []string{"/", "\x00", "\n"} {
				if strings.Contains(l.Name, bad) {
					t.Fatalf("lure name %q contains unsafe character %q", l.Name, bad)
				}
			}
		}
	}
}

func TestLureLocationsAreNotEmpty(t *testing.T) {
	for _, v := range []string{"healthcare", "finance", "legal", "technology"} {
		for _, l := range NewKit(v, "corp.local").GenerateLures() {
			if l.Location == "" {
				t.Fatalf("vertical %q lure %q has no location", v, l.Name)
			}
		}
	}
}

func TestLureTypesAreKnown(t *testing.T) {
	known := map[string]bool{
		"document": true, "database-record": true, "share-folder": true,
		"email-draft": true, "registry-key": true,
	}
	for _, v := range []string{"healthcare", "finance", "legal", "technology", "generic"} {
		for _, l := range NewKit(v, "corp.local").GenerateLures() {
			if !known[l.Type] {
				t.Fatalf("lure %q has unknown type %q", l.Name, l.Type)
			}
		}
	}
}

func TestDPIAContainsLegalBasis(t *testing.T) {
	dpia := DPIATemplate("Test Corp", "dpo@test.com")
	for _, must := range []string{"Article 6", "GDPR", "legitimate interest", "IMPACT ASSESSMENT"} {
		if !strings.Contains(dpia, must) {
			t.Fatalf("DPIA template missing required text: %q", must)
		}
	}
}

func TestPolicyTemplateCoversDeception(t *testing.T) {
	pol := PolicyTemplate("Test Corp")
	for _, must := range []string{"deception", "decoy", "incident response"} {
		if !strings.Contains(strings.ToLower(pol), must) {
			t.Fatalf("policy template missing required text: %q", must)
		}
	}
}

func TestDPIASpecialCharsInOrgName(t *testing.T) {
	dpia := DPIATemplate(`O'Brien & Co "Ltd"`, "dpo@test.com")
	if !strings.Contains(dpia, `O'Brien & Co "Ltd"`) {
		t.Fatal("DPIA did not preserve special characters in org name")
	}
}
