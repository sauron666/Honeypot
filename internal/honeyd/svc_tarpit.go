package honeyd

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("tarpit", newTarpit) }

// tarpitSvc is a LaBrea-style sticky service: it accepts a connection on an
// unused port and holds it open as long as possible, trickling a plausible
// banner one small chunk at a time so the attacker's tool waits for a response
// that never fully arrives. It is legal cognitive friction (idea 15) — it steals
// the attacker's time without a single packet leaving toward anyone else.
//
// Containment: it only ever writes a handful of bytes, slowly (no amplification),
// never reaches outward, and releases after a hard cap so a decoy cannot be used
// to exhaust its own file descriptors. The time it consumes shows up as the
// engagement's duration, which feeds the ROI metric (idea 17).
type tarpitSvc struct {
	p        *Persona
	holdMax  time.Duration
	trickle  time.Duration
	banner   string
	maxConns int64
}

// active counts tarpitted connections across all tarpit listeners, so a flood
// cannot hold more sockets than the cap.
var tarpitActive int64

func newTarpit(p *Persona, opts map[string]any) (Service, error) {
	t := &tarpitSvc{
		p:        p,
		holdMax:  5 * time.Minute,
		trickle:  10 * time.Second,
		banner:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
		maxConns: 512,
	}
	if d, ok := durationOpt(opts["hold_max"]); ok {
		t.holdMax = d
	}
	if d, ok := durationOpt(opts["trickle_every"]); ok && d > 0 {
		t.trickle = d
	}
	if v, ok := opts["banner"].(string); ok && v != "" {
		t.banner = v
	}
	if v, ok := opts["max_conns"].(int); ok && v > 0 {
		t.maxConns = int64(v)
	}
	return t, nil
}

func (t *tarpitSvc) Type() string { return "tarpit" }

func (t *tarpitSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	// Respect the global cap: if too many connections are already stuck, let
	// this one go rather than risk exhausting descriptors.
	if atomic.AddInt64(&tarpitActive, 1) > t.maxConns {
		atomic.AddInt64(&tarpitActive, -1)
		return nil
	}
	defer atomic.AddInt64(&tarpitActive, -1)

	start := time.Now()
	e := s.Event(event.ClassDecoyInteraction, 1, event.SeverityLow).
		WithMessage("tarpit: holding a scanner on port %d — trickling a banner to waste its time", s.LocalPort())
	e.Set("service", "tarpit")
	s.Emit(e)

	deadline := start.Add(t.holdMax)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// Trickle the banner one byte at a time, then keep the line barely alive.
	// A byte every trickle interval is enough that most clients keep waiting
	// for the end of the greeting.
	data := []byte(t.banner)
	idx := 0
	ticker := time.NewTicker(t.trickle)
	defer ticker.Stop()

	// A goroutine drains and discards whatever the attacker sends, so their
	// write buffer does not fill and drop the connection early.
	go func() {
		buf := make([]byte, 1024)
		for {
			conn.SetReadDeadline(time.Now().Add(t.trickle * 2))
			if _, err := conn.Read(buf); err != nil {
				if time.Now().After(deadline) || ctx.Err() != nil {
					return
				}
				// A read timeout is fine — the attacker is just idling in our trap.
				if isTimeout(err) {
					continue
				}
				return
			}
		}
	}()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return t.release(s, start)
		case <-ticker.C:
			var b byte = ' '
			if idx < len(data) {
				b = data[idx]
				idx++
			}
			conn.SetWriteDeadline(time.Now().Add(t.trickle))
			if _, err := conn.Write([]byte{b}); err != nil {
				return t.release(s, start) // attacker gave up — good
			}
			s.Record("out", []byte{b})
		}
	}
	return t.release(s, start)
}

// release records how long the attacker was held. That duration is the whole
// point: it is time they did not spend on a real target.
func (t *tarpitSvc) release(s *Session, start time.Time) error {
	held := time.Since(start).Round(time.Second)
	e := s.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
		WithMessage("tarpit: released after %s of attacker time consumed", held)
	e.Set("service", "tarpit").Set("held_seconds", int(held.Seconds()))
	s.Emit(e)
	return nil
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// durationOpt reads a duration from a YAML option that may be a string
// ("2m30s") or a number of seconds.
func durationOpt(v any) (time.Duration, bool) {
	switch x := v.(type) {
	case string:
		if d, err := time.ParseDuration(x); err == nil {
			return d, true
		}
	case int:
		return time.Duration(x) * time.Second, true
	case float64:
		return time.Duration(x * float64(time.Second)), true
	}
	return 0, false
}
