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
