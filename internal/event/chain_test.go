package event

import (
	"strings"
	"testing"
)

func sample(msg string) *Event {
	e := New(ClassDecoyInteraction, 1, SeverityMedium, PlaneHoneyd)
	e.Mirage.TenantID = "acme"
	e.Mirage.SiteID = "sofia-dc1"
	e.Mirage.DecoyID = "dcy_web01"
	e.Mirage.Service = "ssh"
	e.Metadata.Product = Product{Name: "MIRAGE", VendorName: "test", Version: "0.0.1"}
	e.WithSrc("198.51.100.7", 51234).WithDst("10.66.0.10", 22, "ssh").WithMessage("%s", msg)
	e.Set("username", "administrator").Set("attempt", 3)
	return e
}

func TestSealAndVerify(t *testing.T) {
	c := NewChain()
	var evs []*Event
	for i := 0; i < 25; i++ {
		e := sample("login attempt")
		if err := c.Seal(e); err != nil {
			t.Fatalf("seal: %v", err)
		}
		evs = append(evs, e)
	}
	if err := Verify(evs, GenesisHash); err != nil {
		t.Fatalf("fresh chain must verify: %v", err)
	}
	seq, head := c.Head()
	if seq != 25 {
		t.Fatalf("head seq = %d, want 25", seq)
	}
	if head != evs[24].Mirage.Chain.Hash {
		t.Fatal("head hash must equal the last sealed event's hash")
	}
	if evs[0].Mirage.Chain.PrevHash != GenesisHash {
		t.Fatal("first event must chain to genesis")
	}
}

func TestVerifyDetectsContentTampering(t *testing.T) {
	c := NewChain()
	evs := make([]*Event, 3)
	for i := range evs {
		evs[i] = sample("login attempt")
		if err := c.Seal(evs[i]); err != nil {
			t.Fatal(err)
		}
	}

	// An attacker who owns the log file rewrites the username they used.
	evs[1].Set("username", "nobody")

	err := Verify(evs, GenesisHash)
	if err == nil {
		t.Fatal("tampered event must not verify")
	}
	var ve *VerifyError
	if !asVerifyError(err, &ve) {
		t.Fatalf("want *VerifyError, got %T", err)
	}
	if ve.Index != 1 {
		t.Fatalf("break reported at index %d, want 1", ve.Index)
	}
	if !strings.Contains(ve.Reason, "hash") {
		t.Fatalf("reason %q should name the hash mismatch", ve.Reason)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	c := NewChain()
	evs := make([]*Event, 4)
	for i := range evs {
		evs[i] = sample("cmd")
		if err := c.Seal(evs[i]); err != nil {
			t.Fatal(err)
		}
	}
	// Splicing an event out is the most likely tampering: it hides one action.
	spliced := []*Event{evs[0], evs[2], evs[3]}
	if err := Verify(spliced, GenesisHash); err == nil {
		t.Fatal("deleting an event must break the chain")
	}
}

func TestVerifyDetectsReorder(t *testing.T) {
	c := NewChain()
	evs := make([]*Event, 3)
	for i := range evs {
		evs[i] = sample("cmd")
		if err := c.Seal(evs[i]); err != nil {
			t.Fatal(err)
		}
	}
	swapped := []*Event{evs[1], evs[0], evs[2]}
	if err := Verify(swapped, GenesisHash); err == nil {
		t.Fatal("reordering must break the chain")
	}
}

func TestResumeChainContinuesAcrossRestart(t *testing.T) {
	c := NewChain()
	first := sample("before restart")
	if err := c.Seal(first); err != nil {
		t.Fatal(err)
	}
	seq, head := c.Head()

	// Simulate a process restart that reloads the chain head from storage.
	c2 := ResumeChain(seq, head)
	second := sample("after restart")
	if err := c2.Seal(second); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]*Event{first, second}, GenesisHash); err != nil {
		t.Fatalf("resumed chain must verify: %v", err)
	}
	if second.Mirage.Chain.Seq != 2 {
		t.Fatalf("seq = %d, want 2", second.Mirage.Chain.Seq)
	}
}

func TestCanonicalRoundTripPreservesHash(t *testing.T) {
	c := NewChain()
	e := sample("round trip")
	if err := c.Seal(e); err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	// A decoded event must still verify: storage round-trips must not silently
	// invalidate evidence.
	if err := Verify([]*Event{back}, GenesisHash); err != nil {
		t.Fatalf("decoded event failed verification: %v", err)
	}
	again, err := CanonicalJSON(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(again) {
		t.Fatalf("canonical encoding is not stable across round trip:\n%s\n%s", raw, again)
	}
}

func TestCanonicalIsStableAcrossMapOrder(t *testing.T) {
	a := sample("x")
	a.Metadata.UID = "FIXED"
	a.Time = 1700000000000
	a.Set("z", 1).Set("a", 2).Set("m", 3)

	b := sample("x")
	b.Metadata.UID = "FIXED"
	b.Time = 1700000000000
	b.Set("m", 3).Set("a", 2).Set("z", 1)

	ja, _ := CanonicalJSON(a)
	jb, _ := CanonicalJSON(b)
	if string(ja) != string(jb) {
		t.Fatalf("map insertion order leaked into the encoding:\n%s\n%s", ja, jb)
	}
}

func asVerifyError(err error, target **VerifyError) bool {
	v, ok := err.(*VerifyError)
	if ok {
		*target = v
	}
	return ok
}

// TestChainSurvivesInvalidUTF8 reproduces the anti-forensics bug a live pentest
// found: an attacker who sends invalid UTF-8 (an LDAP bind with a 0x80 byte, a
// binary payload) to a service that records a transcript could make the whole
// evidence chain read as TAMPERED after a store round-trip. The invalid byte was
// encoded as the escape � at seal but decoded back as a real U+FFFD on
// reload, changing the hashed bytes. The chain must now survive it.
func TestChainSurvivesInvalidUTF8(t *testing.T) {
	c := NewChain()
	e := sample("ldap bind")
	// Put raw invalid UTF-8 into a recorded field, as an attacker would.
	e.Set("transcript", ">> \x80\x81\xfe bind\n")
	e.Set("raw_username", "admin\xff")
	if err := c.Seal(e); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Simulate the storage round-trip: canonical-encode, then decode, exactly as
	// the store writes to disk and reloads on restart.
	raw, err := CanonicalJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify([]*Event{back}, GenesisHash); err != nil {
		t.Fatalf("invalid UTF-8 in a field must NOT break the chain: %v", err)
	}
	// And a genuine tamper on such an event is still caught.
	back.Set("transcript", "tampered")
	if err := Verify([]*Event{back}, GenesisHash); err == nil {
		t.Fatal("a real change to an invalid-UTF-8 event must still be detected")
	}
}
