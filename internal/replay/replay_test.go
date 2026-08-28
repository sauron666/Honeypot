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
