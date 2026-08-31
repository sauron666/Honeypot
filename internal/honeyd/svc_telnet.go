package honeyd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("telnet", newTelnet) }

// telnetSvc emulates a telnet server. Telnet decoys catch the loudest, least
// careful traffic on the internet -- IoT botnet loaders in particular -- and
// they cost nothing to run.
type telnetSvc struct {
	p          *Persona
	maxAttempt int
}

func newTelnet(p *Persona, opts map[string]any) (Service, error) {
	t := &telnetSvc{p: p, maxAttempt: 3}
	if v, ok := opts["max_attempts"].(int); ok && v > 0 {
		t.maxAttempt = v
	}
	return t, nil
}

func (t *telnetSvc) Type() string { return "telnet" }

// Telnet protocol bytes we care about.
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
	echo = 1
)

func (t *telnetSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)
	w := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		s.Record("out", []byte(msg))
		_, err := conn.Write([]byte(msg))
		return err
	}

	// Announce that we will echo, the way a real telnetd does.
	conn.Write([]byte{iac, will, echo, iac, will, 3 /* suppress go ahead */})

	if err := w("\r\n%s\r\n%s login: ", t.p.TelnetBanner, t.p.Hostname); err != nil {
		return err
	}

	for attempt := 1; attempt <= t.maxAttempt; attempt++ {
		user, err := readTelnetLine(r, s, conn, true)
		if err != nil {
			return err
		}
		if err := w("Password: "); err != nil {
			return err
		}
		// Suppress echo for the password, as a real server does.
		conn.Write([]byte{iac, will, echo})
		pass, err := readTelnetLine(r, s, conn, false)
		if err != nil {
			return err
		}
		conn.Write([]byte{iac, wont, echo})

		accepted := t.p.AcceptsLogin(user, pass)
		s.AddCredential(Credential{Username: user, Secret: pass, Method: "password", Accepted: accepted})

		if !accepted {
			// Real telnetd is slow to reject; matching that timing matters,
			// because instant rejection is a honeypot tell.
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
			if attempt == t.maxAttempt {
				w("\r\nLogin incorrect\r\n")
				return nil
			}
			if err := w("\r\nLogin incorrect\r\n%s login: ", t.p.Hostname); err != nil {
				return err
			}
			continue
		}

		s.Note(event.SeverityHigh, "telnet login accepted for %q", user)
		return t.shell(ctx, conn, r, s, user, w)
	}
	return nil
}

func (t *telnetSvc) shell(ctx context.Context, conn net.Conn, r *bufio.Reader, s *Session, user string,
	w func(string, ...any) error) error {

	sh := NewShell(t.p, s, user)
	if err := w("\r\n%s", strings.ReplaceAll(sh.Banner(), "\n", "\r\n")); err != nil {
		return err
	}
	for {
		if err := w("\r\n%s", sh.Prompt()); err != nil {
			return err
		}
		line, err := readTelnetLine(r, s, conn, true)
		if err != nil {
			return err
		}
		out, exit := sh.Execute(line)
		if out != "" {
			if err := w("\r\n%s", strings.ReplaceAll(strings.TrimSuffix(out, "\n"), "\n", "\r\n")); err != nil {
				return err
			}
		}
		if exit {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// readTelnetLine reads one line, stripping telnet option negotiation and
// bounding the length so a client cannot feed us an endless line.
func readTelnetLine(r *bufio.Reader, s *Session, conn net.Conn, record bool) (string, error) {
	var b strings.Builder
	for b.Len() < 4096 {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch c {
		case iac:
			cmd, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			switch cmd {
			case do, dont, will, wont:
				if _, err := r.ReadByte(); err != nil { // option byte
					return "", err
				}
			case sb:
				// Skip the sub-negotiation up to IAC SE.
				for {
					x, err := r.ReadByte()
					if err != nil {
						return "", err
					}
					if x == iac {
						y, err := r.ReadByte()
						if err != nil {
							return "", err
						}
						if y == se {
							break
						}
					}
				}
			}
		case '\r':
			// CR may be followed by LF or NUL; consume either.
			if next, err := r.Peek(1); err == nil && (next[0] == '\n' || next[0] == 0) {
				r.ReadByte()
			}
			line := b.String()
			if record {
				s.Record("in", []byte(line))
			}
			return line, nil
		case '\n':
			line := b.String()
			if record {
				s.Record("in", []byte(line))
			}
			return line, nil
		case 0x7f, 0x08: // backspace
			cur := b.String()
			b.Reset()
			if len(cur) > 0 {
				b.WriteString(cur[:len(cur)-1])
			}
		default:
			if c >= 0x20 {
				b.WriteByte(c)
			}
		}
	}
	return b.String(), io.ErrUnexpectedEOF
}
