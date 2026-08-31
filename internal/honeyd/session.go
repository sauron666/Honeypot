// Package honeyd is the emulated service farm: the breadth half of MIRAGE's
// hybrid engagement model. It answers on many addresses and many protocols at
// negligible cost, records everything an attacker does, and escalates to a
// full-OS decoy when the interaction becomes interesting.
//
// Containment rule for everything in this package: a service handler never
// dials outbound, never executes a command, and never touches the host
// filesystem outside the evidence directory. An attacker who owns the protocol
// parser must still own nothing.
package honeyd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/version"
)

// Emitter receives events produced by services.
type Emitter interface {
	Emit(ctx context.Context, e *event.Event)
}

// EmitterFunc adapts a function to Emitter.
type EmitterFunc func(ctx context.Context, e *event.Event)

// Emit calls f.
func (f EmitterFunc) Emit(ctx context.Context, e *event.Event) { f(ctx, e) }

// Identity is the deployment identity stamped on every event.
type Identity struct {
	TenantID string
	SiteID   string
	DecoyID  string
	Persona  string
}

// Session is one attacker interaction with one service. It owns the transcript,
// mints events with the right context already filled in, and enforces the
// resource limits that keep a decoy from becoming a denial-of-service vector.
type Session struct {
	ID           string
	EngagementID string
	Service      string
	Identity     Identity

	Remote   net.Addr
	Local    net.Addr
	Started  time.Time
	Persona  *Persona
	emitter  Emitter
	ctx      context.Context
	deadline time.Time

	mu         sync.Mutex
	transcript bytes.Buffer
	maxScript  int
	truncated  bool
	events     int
	// creds accumulates every credential pair offered, which is often the most
	// valuable single artifact of a session.
	creds []Credential
}

// Credential is one authentication attempt against a decoy.
type Credential struct {
	Username string `json:"username"`
	Secret   string `json:"secret,omitempty"`
	Method   string `json:"method"` // password, publickey, keyboard-interactive, basic, ...
	Accepted bool   `json:"accepted"`
	KeyType  string `json:"key_type,omitempty"`
	KeyPrint string `json:"key_fingerprint,omitempty"`
}

// SrcIP returns the attacker's address without the port.
func (s *Session) SrcIP() string {
	host, _, err := net.SplitHostPort(s.Remote.String())
	if err != nil {
		return s.Remote.String()
	}
	return host
}

// SrcPort returns the attacker's source port.
func (s *Session) SrcPort() int {
	_, port, err := net.SplitHostPort(s.Remote.String())
	if err != nil {
		return 0
	}
	var p int
	fmt.Sscanf(port, "%d", &p)
	return p
}

// LocalPort returns the port the decoy answered on.
func (s *Session) LocalPort() int {
	if s.Local == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(s.Local.String())
	if err != nil {
		return 0
	}
	var p int
	fmt.Sscanf(port, "%d", &p)
	return p
}

// LocalIP returns the decoy address the attacker connected to.
func (s *Session) LocalIP() string {
	if s.Local == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(s.Local.String())
	if err != nil {
		return s.Local.String()
	}
	return host
}

// Event mints an event pre-filled with this session's context.
func (s *Session) Event(class event.Class, activity int, sev event.Severity) *event.Event {
	e := event.New(class, activity, sev, event.PlaneHoneyd)
	e.Metadata.Product = event.Product{
		Name: version.Product, VendorName: version.Vendor, Version: version.Version, Feature: "honeyd",
	}
	e.Mirage.TenantID = s.Identity.TenantID
	e.Mirage.SiteID = s.Identity.SiteID
	e.Mirage.DecoyID = s.Identity.DecoyID
	e.Mirage.Persona = s.Identity.Persona
	e.Mirage.EngagementID = s.EngagementID
	e.Mirage.Service = s.Service
	e.Actor = &event.Actor{Session: s.ID}
	e.WithSrc(s.SrcIP(), s.SrcPort())
	e.WithDst(s.LocalIP(), s.LocalPort(), s.Service)
	return e
}

// Emit publishes an event. It is safe for concurrent use.
func (s *Session) Emit(e *event.Event) {
	s.mu.Lock()
	s.events++
	s.mu.Unlock()
	s.emitter.Emit(s.ctx, e)
}

// Record appends to the session transcript. The transcript is capped: an
// attacker who pipes a gigabyte at us must not be able to exhaust memory, and
// the truncation is recorded rather than hidden.
func (s *Session) Record(direction string, b []byte) {
	if len(b) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transcript.Len() >= s.maxScript {
		s.truncated = true
		return
	}
	prefix := "<< "
	if direction == "in" {
		prefix = ">> "
	}
	remaining := s.maxScript - s.transcript.Len()
	if len(b) > remaining {
		b = b[:remaining]
		s.truncated = true
	}
	s.transcript.WriteString(prefix)
	s.transcript.Write(sanitize(b))
	s.transcript.WriteByte('\n')
}

// sanitize renders control characters readably so a transcript can be shown in
// a browser without turning into terminal escape soup, and so an attacker
// cannot inject escape sequences into an analyst's terminal.
//
// It is rune-aware for a second, non-cosmetic reason: an attacker who sends
// invalid UTF-8 (an LDAP bind with a 0x80 byte, a binary payload) must not be
// able to poison the evidence. A raw invalid byte left in a string is re-coded
// by encoding/json as U+FFFD on the way out and decoded back differently on
// reload, which changes the bytes the hash chain covers and makes honest
// evidence read as TAMPERED -- an anti-forensics vector. Escaping every invalid
// byte as \xNN keeps the transcript valid UTF-8 and, crucially, preserves the
// exact byte the attacker sent (the � you would otherwise see loses it).
func sanitize(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			out = append(out, '\\', 'n')
			i++
		case c == '\r':
			out = append(out, '\\', 'r')
			i++
		case c == '\t':
			out = append(out, '\\', 't')
			i++
		case c < 0x20 || c == 0x7f:
			out = append(out, fmt.Sprintf("\\x%02x", c)...)
			i++
		case c < 0x80:
			out = append(out, c)
			i++
		default:
			// A multi-byte rune: pass it through only if it is valid UTF-8;
			// otherwise escape the single offending byte and advance one.
			r, size := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && size <= 1 {
				out = append(out, fmt.Sprintf("\\x%02x", c)...)
				i++
			} else {
				out = append(out, b[i:i+size]...)
				i += size
			}
		}
	}
	return out
}

// Transcript returns the recorded conversation and whether it was truncated.
func (s *Session) Transcript() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transcript.String(), s.truncated
}

// AddCredential records an authentication attempt and emits an event for it.
// Credentials are the single most reusable artifact a decoy produces: they feed
// password-spray detection and tell you which of your real accounts are known
// to the attacker.
func (s *Session) AddCredential(c Credential) {
	s.mu.Lock()
	s.creds = append(s.creds, c)
	n := len(s.creds)
	s.mu.Unlock()

	sev := event.SeverityMedium
	if c.Accepted {
		sev = event.SeverityHigh
	}
	e := s.Event(event.ClassCredentialOffer, 1, sev).
		WithMessage("credentials offered to %s decoy: %s", s.Service, redactUser(c.Username)).
		WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
	e.Actor.User = c.Username
	e.Set("username", c.Username).
		Set("secret", c.Secret).
		Set("auth_method", c.Method).
		Set("accepted", c.Accepted).
		Set("attempt", n)
	if c.KeyPrint != "" {
		e.Set("key_type", c.KeyType).Set("key_fingerprint", c.KeyPrint)
	}
	s.Emit(e)
}

func redactUser(u string) string {
	if u == "" {
		return "<empty>"
	}
	if len(u) > 64 {
		return u[:64] + "..."
	}
	return u
}

// Credentials returns a copy of everything offered this session.
func (s *Session) Credentials() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Credential(nil), s.creds...)
}

// Command records an attacker command and emits it. This is the event an
// analyst actually reads.
func (s *Session) Command(cmd string, sev event.Severity, techniques ...event.Technique) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	if len(cmd) > 4096 {
		cmd = cmd[:4096] + "...[truncated]"
	}
	e := s.Event(event.ClassCommandExecuted, 1, sev).
		WithMessage("command: %s", cmd).
		WithAttack(techniques...)
	e.Set("command", cmd)
	s.Emit(e)
}

// Note emits a free-form observation about the session.
func (s *Session) Note(sev event.Severity, format string, args ...any) {
	s.Emit(s.Event(event.ClassDecoyInteraction, 99, sev).WithMessage(format, args...))
}

// EventCount reports how many events this session produced.
func (s *Session) EventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events
}

// Deadline returns when the session is force-closed.
func (s *Session) Deadline() time.Time { return s.deadline }

// Context returns the session context, cancelled on shutdown.
func (s *Session) Context() context.Context { return s.ctx }
