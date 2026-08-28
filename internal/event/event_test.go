package event

import (
	"sort"
	"sync"
	"testing"
)

func TestValidateRejectsIncompleteEvents(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Event)
		want error
	}{
		{"no time", func(e *Event) { e.Time = 0 }, ErrNoTime},
		{"no class", func(e *Event) { e.ClassUID = 0 }, ErrNoClass},
		{"no uid", func(e *Event) { e.Metadata.UID = "" }, ErrNoUID},
		{"no severity", func(e *Event) { e.SeverityID = 0 }, ErrNoSeverity},
		{"no plane", func(e *Event) { e.Mirage.Plane = "" }, ErrNoPlane},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := sample("v")
			tc.mut(e)
			if err := e.Validate(); err != tc.want {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
	if err := sample("v").Validate(); err != nil {
		t.Fatalf("a complete event must validate: %v", err)
	}
}

func TestTypeUIDAndCategory(t *testing.T) {
	e := New(ClassAuthentication, 2, SeverityHigh, PlaneHoneyd)
	if e.TypeUID != 300202 {
		t.Fatalf("type_uid = %d, want 300202", e.TypeUID)
	}
	if e.CategoryUID != 3 {
		t.Fatalf("category = %d, want 3 (IAM)", e.CategoryUID)
	}
	if got := New(ClassDecoyInteraction, 1, SeverityLow, PlaneHoneyd).CategoryUID; got != 9 {
		t.Fatalf("MIRAGE extension category = %d, want 9", got)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	e := sample("orig")
	e.WithAttack(Technique{Technique: "T1110.001"})
	cp := e.Clone()
	cp.Set("username", "changed")
	cp.Src.IP = "203.0.113.1"
	cp.Mirage.Attack[0].Technique = "T0000"

	if e.GetString("username") != "administrator" {
		t.Fatal("clone shares the Data map with the original")
	}
	if e.Src.IP != "198.51.100.7" {
		t.Fatal("clone shares the Src endpoint with the original")
	}
	if e.Mirage.Attack[0].Technique != "T1110.001" {
		t.Fatal("clone shares the Attack slice with the original")
	}
}

func TestNewIDIsSortableAndUnique(t *testing.T) {
	const n = 5000
	ids := make([]string, n)
	for i := range ids {
		ids[i] = NewID()
	}
	seen := make(map[string]bool, n)
	for _, id := range ids {
		if len(id) != 26 {
			t.Fatalf("id %q has length %d, want 26", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
	// IDs minted in order must already be sorted: analysts rely on lexical
	// order matching creation order.
	if !sort.StringsAreSorted(ids) {
		t.Fatal("IDs minted in sequence are not lexicographically sorted")
	}
}

func TestNewIDConcurrent(t *testing.T) {
	var (
		mu  sync.Mutex
		all = map[string]bool{}
		wg  sync.WaitGroup
	)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 500)
			for i := range local {
				local[i] = NewID()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if all[id] {
					t.Errorf("duplicate id under concurrency: %s", id)
				}
				all[id] = true
			}
		}()
	}
	wg.Wait()
}

func TestSealIsSafeUnderConcurrency(t *testing.T) {
	c := NewChain()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Seal(sample("concurrent")); err != nil {
				t.Errorf("seal: %v", err)
			}
		}()
	}
	wg.Wait()
	seq, _ := c.Head()
	if seq != 50 {
		t.Fatalf("sealed %d events, want 50", seq)
	}
}
