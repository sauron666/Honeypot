package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func newEvent(msg string, sev event.Severity) *event.Event {
	e := event.New(event.ClassDecoyInteraction, 1, sev, event.PlaneHoneyd)
	e.Mirage.TenantID = "acme"
	e.Mirage.SiteID = "site1"
	e.Mirage.Service = "ssh"
	e.Mirage.DecoyID = "dcy_1"
	e.WithSrc("198.51.100.7", 4444).WithMessage("%s", msg)
	return e
}

func openTemp(t *testing.T, opts FileOptions) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := OpenFile(path, opts)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestAppendPersistsAndVerifies(t *testing.T) {
	s, path := openTemp(t, DefaultFileOptions())
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := s.Append(ctx, newEvent("hit", event.SeverityMedium)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st := s.Stats(); st.Events != 10 || st.HeadSeq != 10 {
		t.Fatalf("stats = %+v, want 10 events", st)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n != 10 {
		t.Fatalf("evidence file has %d lines, want 10", n)
	}
}

func TestReopenResumesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	ctx := context.Background()

	s1, err := OpenFile(path, DefaultFileOptions())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s1.Append(ctx, newEvent("first run", event.SeverityLow)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenFile(path, DefaultFileOptions())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	if seq, _ := s2.Head(); seq != 5 {
		t.Fatalf("resumed head seq = %d, want 5", seq)
	}
	if err := s2.Append(ctx, newEvent("second run", event.SeverityLow)); err != nil {
		t.Fatal(err)
	}
	// The chain has to span the restart, otherwise a restart would be an easy
	// way to launder tampered evidence.
	if err := s2.Verify(ctx); err != nil {
		t.Fatalf("chain must span the restart: %v", err)
	}
	if st := s2.Stats(); st.Events != 6 {
		t.Fatalf("events = %d, want 6", st.Events)
	}
}

func TestVerifyDetectsEditedFile(t *testing.T) {
	s, path := openTemp(t, DefaultFileOptions())
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := s.Append(ctx, newEvent("hit", event.SeverityMedium)); err != nil {
			t.Fatal(err)
		}
	}
	s.Flush()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), "198.51.100.7", "203.0.113.9", 1)
	if edited == string(raw) {
		t.Fatal("test setup: nothing was edited")
	}
	if err := os.WriteFile(path, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := s.Verify(ctx); err == nil {
		t.Fatal("editing the evidence file must fail verification")
	}
}

func TestVerifyDetectsRemovedLine(t *testing.T) {
	s, path := openTemp(t, DefaultFileOptions())
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := s.Append(ctx, newEvent("hit", event.SeverityMedium)); err != nil {
			t.Fatal(err)
		}
	}
	s.Flush()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	kept := append(append([]string{}, lines[0]), lines[2:]...)
	os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o640)

	if err := s.Verify(ctx); err == nil {
		t.Fatal("deleting a line must fail verification")
	}
}

func TestQueryFilters(t *testing.T) {
	s, _ := openTemp(t, DefaultFileOptions())
	ctx := context.Background()

	a := newEvent("ssh brute force", event.SeverityHigh)
	a.Mirage.Service = "ssh"
	b := newEvent("http scan", event.SeverityLow)
	b.Mirage.Service = "http"
	b.Src.IP = "203.0.113.5"
	c := newEvent("ssh command", event.SeverityCritical)
	c.Mirage.Service = "ssh"
	c.Set("command", "cat /etc/shadow")

	for _, e := range []*event.Event{a, b, c} {
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"all", Query{}, 3},
		{"by service", Query{Service: "ssh"}, 2},
		{"by src ip", Query{SrcIP: "203.0.113.5"}, 1},
		{"min severity high", Query{MinSeverity: event.SeverityHigh}, 2},
		{"search message", Query{Search: "brute"}, 1},
		{"search data value", Query{Search: "/etc/shadow"}, 1},
		{"by plane", Query{Plane: event.PlaneHoneyd}, 3},
		{"wrong plane", Query{Plane: event.PlaneTap}, 0},
		{"limit", Query{Limit: 2}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Query(ctx, tc.q)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d events, want %d", len(got), tc.want)
			}
		})
	}
}

func TestQueryOrderingAndPaging(t *testing.T) {
	s, _ := openTemp(t, DefaultFileOptions())
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e := newEvent("n", event.SeverityLow)
		e.Time = int64(1700000000000 + i*1000)
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	desc, _ := s.Query(ctx, Query{})
	if desc[0].Time != 1700000004000 {
		t.Fatalf("default order must be newest first, got %d", desc[0].Time)
	}
	asc, _ := s.Query(ctx, Query{Ascending: true})
	if asc[0].Time != 1700000000000 {
		t.Fatalf("ascending order broken, got %d", asc[0].Time)
	}
	page2, _ := s.Query(ctx, Query{Limit: 2, Offset: 2})
	if len(page2) != 2 || page2[0].Time != 1700000002000 {
		t.Fatalf("paging broken: %v", page2)
	}
}

func TestQueryFallsBackToFileBeyondMemoryWindow(t *testing.T) {
	// A tiny window forces eviction; old evidence must still be queryable.
	s, _ := openTemp(t, FileOptions{MemoryWindow: 3, SyncEvery: 1})
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		e := newEvent("aged", event.SeverityLow)
		e.Time = int64(1700000000000 + i*1000)
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.Stats(); !st.Truncated || st.InMemory != 3 {
		t.Fatalf("expected a truncated 3-event window, got %+v", st)
	}

	old, err := s.Query(ctx, Query{Since: time.UnixMilli(1700000000000), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 20 {
		t.Fatalf("file fallback returned %d events, want 20", len(old))
	}
}

func TestGetByUID(t *testing.T) {
	s, _ := openTemp(t, DefaultFileOptions())
	ctx := context.Background()
	e := newEvent("find me", event.SeverityLow)
	if err := s.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, e.Metadata.UID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Metadata.UID != e.Metadata.UID {
		t.Fatal("wrong event returned")
	}
	if _, err := s.Get(ctx, "NOPE"); err != ErrNotFound {
		t.Fatalf("missing uid: got %v, want ErrNotFound", err)
	}
}

func TestAppendRejectsInvalidEvent(t *testing.T) {
	s, _ := openTemp(t, DefaultFileOptions())
	bad := newEvent("x", event.SeverityLow)
	bad.Mirage.Plane = ""
	if err := s.Append(context.Background(), bad); err == nil {
		t.Fatal("invalid events must never reach the evidence file")
	}
	if st := s.Stats(); st.Events != 0 {
		t.Fatalf("rejected event was counted: %+v", st)
	}
}

func TestCorruptLineIsReportedOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("{\"time\":1,\"class_uid\":9001\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, DefaultFileOptions()); err == nil {
		t.Fatal("a truncated evidence file must be reported, not silently accepted")
	}
}

func TestQueryOrdersByEventTimeNotInsertionOrder(t *testing.T) {
	// Concurrent decoy sessions interleave, so an event created earlier can be
	// sealed later. A timeline an analyst reads must follow when things
	// happened, not the order the chain happened to seal them.
	s, _ := openTemp(t, DefaultFileOptions())
	ctx := context.Background()

	late := newEvent("later event", event.SeverityLow)
	late.Time = 1700000005000
	early := newEvent("earlier event", event.SeverityLow)
	early.Time = 1700000001000

	if err := s.Append(ctx, late); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, early); err != nil {
		t.Fatal(err)
	}

	asc, err := s.Query(ctx, Query{Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	if asc[0].Message != "earlier event" {
		t.Fatalf("ascending order = %q first, want the earlier event", asc[0].Message)
	}
	desc, err := s.Query(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if desc[0].Message != "later event" {
		t.Fatalf("descending order = %q first, want the later event", desc[0].Message)
	}
	// Sorting must not disturb the chain itself.
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("chain broken after querying: %v", err)
	}
}
