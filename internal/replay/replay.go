// Package replay records SSH/telnet sessions in asciinema v2 format so they
// can be replayed in a terminal or embedded in the UI.
//
// An evidence chain records what happened; a replay shows what it looked like.
// For an analyst triaging an intrusion, seeing the attacker's terminal in real
// time — their typing speed, their hesitations, the commands they deleted
// before running — is the difference between reading a log and understanding
// an actor.
package replay

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Recording is one session capture.
type Recording struct {
	started time.Time
	events  []entry
}

type entry struct {
	offset  float64 // seconds since start
	typ     string  // "o" (output) or "i" (input)
	payload string
}

// New creates a recording starting now.
func New() *Recording {
	return &Recording{started: time.Now()}
}

// NewAt creates a recording starting at a given time (for tests).
func NewAt(t time.Time) *Recording {
	return &Recording{started: t}
}

// Output records data sent to the terminal (what the attacker sees).
func (r *Recording) Output(data string) {
	r.events = append(r.events, entry{
		offset:  time.Since(r.started).Seconds(),
		typ:     "o",
		payload: data,
	})
}

// Input records data sent by the attacker (what they typed).
func (r *Recording) Input(data string) {
	r.events = append(r.events, entry{
		offset:  time.Since(r.started).Seconds(),
		typ:     "i",
		payload: data,
	})
}

// OutputAt records output at a specific offset (for tests or reconstruction).
func (r *Recording) OutputAt(offset float64, data string) {
	r.events = append(r.events, entry{offset: offset, typ: "o", payload: data})
}

// InputAt records input at a specific offset.
func (r *Recording) InputAt(offset float64, data string) {
	r.events = append(r.events, entry{offset: offset, typ: "i", payload: data})
}

// Asciinema renders the recording in asciinema v2 format: a JSON header line
// followed by one [time, type, data] JSON array per event.
//
// This format is directly playable by `asciinema play`, the asciinema web
// player, and any tool that reads v2 .cast files.
func (r *Recording) Asciinema(width, height int, title string) string {
	if width <= 0 {
		width = 120
	}
	if height <= 0 {
		height = 40
	}

	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": r.started.Unix(),
		"env": map[string]string{
			"SHELL": "/bin/bash",
			"TERM":  "xterm-256color",
		},
	}
	if title != "" {
		header["title"] = title
	}

	var b strings.Builder
	hdr, _ := json.Marshal(header)
	b.Write(hdr)
	b.WriteByte('\n')

	for _, e := range r.events {
		line, _ := json.Marshal([]any{e.offset, e.typ, e.payload})
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// Duration returns the total recording time.
func (r *Recording) Duration() time.Duration {
	if len(r.events) == 0 {
		return 0
	}
	return time.Duration(r.events[len(r.events)-1].offset * float64(time.Second))
}

// EventCount returns how many events were recorded.
func (r *Recording) EventCount() int { return len(r.events) }

// Summary returns a one-line description.
func (r *Recording) Summary() string {
	return fmt.Sprintf("%d events, %.1f seconds", len(r.events), r.Duration().Seconds())
}
