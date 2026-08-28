// Package life makes a decoy look inhabited.
//
// A static decoy betrays itself over time. An attacker who lands on a "busy"
// application server, runs `last` twice ten minutes apart and sees the exact
// same final login both times, or reads /var/log/auth.log and finds the newest
// line is hours old and never moves, has learned the machine is a stage set.
// Real hosts breathe: people log in and out, cron runs, services restart,
// files appear in /tmp and caches.
//
// The naive way to fake that is a background goroutine that mutates the decoy's
// state on a timer. It is also the wrong way. It races every attacker read of
// the same filesystem, it needs locking threaded through code that was written
// single-owner, and worst of all a metronome is itself a tell -- a new log line
// exactly every ninety seconds is not how anything real behaves.
//
// So life here is a pure function of wall-clock time. Given the deployment seed
// and a moment, the Engine computes the activity that *would have happened* up
// to that moment: a deterministic, seeded, human-shaped schedule of logins,
// cron runs and file writes. Nothing is stored and nothing mutates. Two reads a
// second apart return the same history; a read after the next scheduled event
// has passed returns one more entry. Restart-safe by construction, different
// between installations because the seed is, and -- crucially -- it emits no
// events, so synthetic activity can never be mistaken for an attacker in the
// evidence chain.
package life

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Window is how far back the engine renders activity. A month of history is
// enough to look established without making `last` scroll forever.
const Window = 30 * 24 * time.Hour

// Actor is someone or something that logs in.
type Actor struct {
	// User is the account name as it appears in logs and `last`.
	User string
	// Service marks a non-interactive account (a backup job, a monitoring
	// agent) whose logins are frequent, brief and from fixed hosts.
	Service bool
	// Home is where interactive activity leaves files, when known.
	Home string
}

// Engine renders a decoy's synthetic life.
//
// It holds no clock and no state: every method takes the moment to render for,
// so the caller's `time.Now()` is the only source of "now" and tests can pin it.
type Engine struct {
	seed    string
	host    string
	domain  string
	subnet  string // the internal network logins appear to come from
	actors  []Actor
	windows bool
}

// Options configures an Engine.
type Options struct {
	Seed    string
	Host    string
	Domain  string
	Actors  []Actor
	Windows bool
	// Subnet is the internal range synthetic logins come from, e.g.
	// "10.20.30". A decoy whose only logins are from the attacker's own subnet
	// looks abandoned; one whose synthetic logins come from a plausible office
	// range looks used.
	Subnet string
}

// New builds an Engine. It never fails: a decoy with no declared actors simply
// invents a couple of plausible ones, because a host with genuinely zero login
// history is itself unusual enough to notice.
func New(opt Options) *Engine {
	e := &Engine{
		seed: opt.Seed, host: opt.Host, domain: opt.Domain,
		actors: opt.Actors, windows: opt.Windows, subnet: opt.Subnet,
	}
	if e.subnet == "" {
		e.subnet = "10.10.10"
	}
	if len(e.actors) == 0 {
		e.actors = []Actor{
			{User: "admin", Home: "/home/admin"},
			{User: "backup", Service: true},
		}
	}
	return e
}

// Login is one recorded session.
type Login struct {
	User    string
	From    string // source address
	Start   time.Time
	End     time.Time // zero if the session is still open
	Service bool
}

// Duration is how long the session lasted, or how long it has been open.
func (l Login) Duration(now time.Time) time.Duration {
	if l.End.IsZero() {
		return now.Sub(l.Start)
	}
	return l.End.Sub(l.Start)
}

// StillLoggedIn reports whether the session is open at now.
func (l Login) StillLoggedIn() bool { return l.End.IsZero() }

// Logins returns every synthetic session active or ended within the window
// before now, newest first -- which is the order `last` prints.
func (e *Engine) Logins(now time.Time) []Login {
	var out []Login
	start := now.Add(-Window)

	for _, a := range e.actors {
		// Each actor's rhythm is deterministic in the seed, so the same decoy
		// always tells the same story, and two decoys never tell the same one.
		out = append(out, e.actorLogins(a, start, now)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out
}

// actorLogins schedules one actor's sessions across the window.
func (e *Engine) actorLogins(a Actor, start, now time.Time) []Login {
	var out []Login

	// Walk day by day. An interactive user logs in most weekdays around the
	// start of the workday and logs out around its end; a service account logs
	// in several times a day at intervals that jitter around a period. Both
	// come out of the seed, so nothing here is random at runtime.
	for day := start.Truncate(24 * time.Hour); !day.After(now); day = day.Add(24 * time.Hour) {
		weekday := day.Weekday()
		if a.Service {
			out = append(out, e.serviceLogins(a, day, now)...)
			continue
		}
		// Interactive users mostly work weekdays. Not never on a weekend --
		// that too would be a pattern -- but rarely.
		if weekday == time.Saturday || weekday == time.Sunday {
			if e.roll(a.User, day, "weekend") > 20 { // ~1 in 5 weekends
				continue
			}
		}
		// A day off now and then.
		if !a.Service && e.roll(a.User, day, "absent") < 8 { // ~8% of days
			continue
		}

		loginHour := 7 + int(e.roll(a.User, day, "hour"))%3 // 07:00-09:59
		loginMin := int(e.roll(a.User, day, "min")) % 60
		workLen := 8*time.Hour + time.Duration(e.roll(a.User, day, "len"))%4*time.Hour

		s := time.Date(day.Year(), day.Month(), day.Day(), loginHour, loginMin, 0, 0, day.Location())
		if s.After(now) {
			continue
		}
		end := s.Add(workLen)
		l := Login{User: a.User, From: e.actorHost(a, day), Start: s, Service: false}
		if end.Before(now) {
			l.End = end
		}
		// else: it is "today" and this person is still logged in, which is the
		// detail that makes `w` show a live session that was not the attacker.
		out = append(out, l)
	}
	return out
}

// serviceLogins schedules a service account's frequent short sessions for a day.
func (e *Engine) serviceLogins(a Actor, day, now time.Time) []Login {
	var out []Login
	// A backup or monitoring account runs on a period with jitter, so the gaps
	// between its logins are close to constant but never exactly.
	period := 2*time.Hour + time.Duration(e.roll(a.User, day, "period"))%2*time.Hour
	from := e.actorHost(a, day)
	for t := day; t.Before(day.Add(24 * time.Hour)); t = t.Add(period) {
		jitter := time.Duration(e.roll(a.User, t, "jit")) % 17 * time.Minute
		s := t.Add(jitter)
		if s.After(now) || s.Before(now.Add(-Window)) {
			continue
		}
		dur := 1*time.Minute + time.Duration(e.roll(a.User, s, "dur"))%9*time.Minute
		l := Login{User: a.User, From: from, Start: s, Service: true}
		if s.Add(dur).Before(now) {
			l.End = s.Add(dur)
		}
		out = append(out, l)
	}
	return out
}

// LastLogon returns the most recent login time for a user at or before now,
// which is what an LDAP lastLogonTimestamp or a Windows LastLogonDate should
// say. A zero time means the account has not logged in within the window.
func (e *Engine) LastLogon(user string, now time.Time) time.Time {
	var latest time.Time
	for _, l := range e.Logins(now) {
		if strings.EqualFold(l.User, user) && l.Start.After(latest) {
			latest = l.Start
		}
	}
	return latest
}

// ActiveNow returns the sessions still open at now: what `w` and `who` show.
func (e *Engine) ActiveNow(now time.Time) []Login {
	var out []Login
	for _, l := range e.Logins(now) {
		if l.StillLoggedIn() {
			out = append(out, l)
		}
	}
	return out
}

// actorHost gives an actor a stable-ish source address. Interactive users move
// around the office subnet day to day; a service account comes from one host.
func (e *Engine) actorHost(a Actor, day time.Time) string {
	if a.Service {
		return fmt.Sprintf("%s.%d", e.subnet, 20+int(e.roll(a.User, time.Time{}, "svc-host"))%10)
	}
	return fmt.Sprintf("%s.%d", e.subnet, 100+int(e.roll(a.User, day, "host"))%80)
}

// roll returns a deterministic byte in [0,100) from the seed, a label and a
// day. It is the single source of every "random" decision here, so the whole
// schedule is reproducible from the seed and nothing else.
func (e *Engine) roll(label string, when time.Time, purpose string) byte {
	key := fmt.Sprintf("%s|life|%s|%s|%d", e.seed, purpose, label, when.Unix())
	sum := sha256.Sum256([]byte(key))
	return byte(binary.BigEndian.Uint32(sum[:4]) % 100)
}
