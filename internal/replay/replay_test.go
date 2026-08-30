package replay

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The asciinema v2 format is a strict line protocol: a JSON header object, then
// one JSON array per event as [offset, type, payload]. A player rejects a file
// that deviates, so these tests pin the format rather than trusting it.

func TestAsciinemaHeaderIsValidV2(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	r.OutputAt(0.5, "hello\r\n")
	out := r.Asciinema(80, 24, "attacker session")

	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Scan()
	var hdr map[string]any
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		t.Fatalf("header is not valid JSON: %v", err)
	}
	if hdr["version"].(float64) != 2 {
		t.Fatalf("asciinema version must be 2, got %v", hdr["version"])
	}
	if hdr["width"].(float64) != 80 || hdr["height"].(float64) != 24 {
		t.Fatalf("geometry lost: %v x %v", hdr["width"], hdr["height"])
	}
	if hdr["timestamp"].(float64) != 1710000000 {
		t.Fatalf("start timestamp lost: %v", hdr["timestamp"])
	}
	if hdr["title"] != "attacker session" {
		t.Fatalf("title lost: %v", hdr["title"])
	}
}

func TestAsciinemaEventsAreWellFormed(t *testing.T) {
	r := New()
	r.OutputAt(0.1, "$ ")
	r.InputAt(0.2, "whoami\r")
	r.OutputAt(0.3, "root\r\n")

	lines := strings.Split(strings.TrimSpace(r.Asciinema(0, 0, "")), "\n")
	if len(lines) != 4 { // header + 3 events
		t.Fatalf("expected header plus 3 events, got %d lines", len(lines))
	}
	// Every event line must be [number, "o"|"i", string], in time order.
	var last float64 = -1
	for _, l := range lines[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("event is not a JSON array: %q", l)
		}
		if len(ev) != 3 {
			t.Fatalf("event must have 3 fields: %q", l)
		}
		off := ev[0].(float64)
		if off < last {
			t.Fatalf("events out of time order: %v after %v", off, last)
		}
		last = off
		typ := ev[1].(string)
		if typ != "o" && typ != "i" {
			t.Fatalf("event type must be o or i, got %q", typ)
		}
	}
}

func TestInputAndOutputAreDistinguished(t *testing.T) {
	// A replay that cannot tell what the attacker typed from what the decoy
	// answered is useless for review.
	r := New()
	r.Output("banner")
	r.Input("secret-command")
	out := r.Asciinema(0, 0, "")
	if !strings.Contains(out, `"i"`) || !strings.Contains(out, `"o"`) {
		t.Fatalf("input/output not distinguished:\n%s", out)
	}
}

func TestDurationTracksLastEvent(t *testing.T) {
	r := New()
	r.OutputAt(2.5, "x")
	if d := r.Duration(); d < 2*time.Second || d > 3*time.Second {
		t.Fatalf("duration wrong: %v", d)
	}
	if New().Duration() != 0 {
		t.Fatal("an empty recording has zero duration")
	}
}

func TestEventCountMatchesRecordedEvents(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	if r.EventCount() != 0 {
		t.Fatal("empty recording has non-zero event count")
	}
	r.OutputAt(0.1, "$ ")
	r.InputAt(0.2, "id\r")
	r.OutputAt(0.3, "uid=0(root)\r\n")
	if got := r.EventCount(); got != 3 {
		t.Fatalf("EventCount = %d, want 3", got)
	}
}

func TestSummaryFormatAndContent(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	r.OutputAt(0.5, "hello")
	r.InputAt(4.0, "cmd")
	s := r.Summary()
	if s != "2 events, 4.0 seconds" {
		t.Fatalf("Summary = %q, want %q", s, "2 events, 4.0 seconds")
	}
}

func TestDefaultDimensionsWhenZeroOrNegative(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	r.OutputAt(0.1, "x")
	out := r.Asciinema(0, -1, "")
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Scan()
	var hdr map[string]any
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["width"].(float64) != 120 || hdr["height"].(float64) != 40 {
		t.Fatalf("default dimensions wrong: %v x %v", hdr["width"], hdr["height"])
	}
}

func TestEmptyTitleIsOmittedFromHeader(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	out := r.Asciinema(80, 24, "")
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Scan()
	var hdr map[string]any
	json.Unmarshal(sc.Bytes(), &hdr)
	if _, ok := hdr["title"]; ok {
		t.Fatal("empty title should not appear in header")
	}
}

func TestEmptyRecordingProducesHeaderOnly(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	out := r.Asciinema(80, 24, "")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("empty recording should produce 1 line (header), got %d", len(lines))
	}
}

func TestSpecialCharactersInPayload(t *testing.T) {
	r := NewAt(time.Unix(1710000000, 0))
	r.OutputAt(0.1, "\x1b[31mred\x1b[0m")
	r.OutputAt(0.2, "quote: \"hello\"")
	r.OutputAt(0.3, "null: \x00 tab: \t")
	out := r.Asciinema(80, 24, "test")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, l := range lines[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("event %d with special chars is not valid JSON: %v", i, err)
		}
	}
}
