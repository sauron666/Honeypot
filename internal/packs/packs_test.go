package packs

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/sauron666/Honeypot/internal/honeyd"
)

// realPersona is the production persona checker, so the tests prove packs
// reference personas that actually exist in the farm.
func realPersona(name string) bool {
	for _, n := range honeyd.PersonaNames() {
		if n == name {
			return true
		}
	}
	return false
}

func TestBuiltinPacksAreValidAgainstRealPersonas(t *testing.T) {
	all, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("expected at least two built-in packs, got %d", len(all))
	}
	for _, p := range all {
		if err := p.Validate(realPersona); err != nil {
			t.Errorf("built-in pack %q is invalid: %v", p.Name, err)
		}
	}
}

func TestValidateRejectsUnknownPersona(t *testing.T) {
	p := &Pack{
		Name: "x", Version: "1.0.0",
		Decoys: []PackDecoy{{
			ID: "d1", Persona: "linux/nonesuch",
			Services: []PackService{{Service: "ssh", Port: 22}},
		}},
	}
	if err := p.Validate(realPersona); err == nil {
		t.Fatal("expected rejection of an unknown persona")
	}
}

func TestValidateRejectsStructuralErrors(t *testing.T) {
	cases := []*Pack{
		{Version: "1.0.0"}, // no name
		{Name: "x"},        // no version
		{Name: "x", Version: "1", Decoys: []PackDecoy{{ID: "d"}}},                       // no persona
		{Name: "x", Version: "1", Decoys: []PackDecoy{{ID: "d", Persona: "linux/web"}}}, // no services
	}
	for i, p := range cases {
		if err := p.Validate(nil); err == nil {
			t.Errorf("case %d should have been rejected", i)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &Pack{
		Name: "finance-en", Version: "1.0.0",
		Decoys: []PackDecoy{{ID: "d1", Persona: "linux/db", Services: []PackService{{Service: "mysql", Port: 3306}}}},
	}
	if err := p.Verify(pub); err != ErrUnsigned {
		t.Fatalf("an unsigned pack should report ErrUnsigned, got %v", err)
	}
	if err := p.Sign(priv, "aa:bb"); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(pub); err != nil {
		t.Fatalf("a freshly signed pack must verify: %v", err)
	}
	// Tamper: change a decoy after signing.
	p.Decoys[0].Services[0].Port = 3307
	if err := p.Verify(pub); err == nil {
		t.Fatal("verification must fail after the pack is tampered with")
	}
}

func TestSummaryMarksUnsigned(t *testing.T) {
	all, _ := Builtin()
	s := all[0].Summary()
	if !strings.Contains(s, "UNSIGNED") {
		t.Error("a built-in unsigned pack summary should say UNSIGNED")
	}
}

func TestParseRoundTrip(t *testing.T) {
	raw := []byte("name: t\nversion: 1.0.0\ndecoys:\n  - id: d1\n    persona: linux/web\n    services:\n      - {service: http, port: 80}\n")
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "t" || len(p.Decoys) != 1 || p.Decoys[0].Services[0].Port != 80 {
		t.Fatalf("parse lost data: %+v", p)
	}
}
