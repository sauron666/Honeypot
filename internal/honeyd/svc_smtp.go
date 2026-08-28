package honeyd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("smtp", newSMTP) }

// smtpSvc emulates a mail server.
//
// Containment is the whole design here: the decoy accepts a message and records
// it, and never delivers anything anywhere. An open relay that actually relays
// is not a honeypot, it is a spam service with logging.
type smtpSvc struct {
	p        *Persona
	hostname string
}

func newSMTP(p *Persona, opts map[string]any) (Service, error) {
	s := &smtpSvc{p: p, hostname: p.Hostname + "." + p.Domain}
	if v, ok := opts["hostname"].(string); ok && v != "" {
		s.hostname = v
	}
	return s, nil
}

func (m *smtpSvc) Type() string { return "smtp" }

type smtpState struct {
	helo       string
	from       string
	recipients []string
	// offeredUser is the username the client tried. Authentication always
	// fails, so this must never be read as "the session is authenticated":
	// treating an offered credential as an accepted one would suppress the
	// open-relay finding, which is the reason the decoy exists.
	offeredUser string
}

func (m *smtpSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)
	st := &smtpState{}

	say := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...) + "\r\n"
		s.Record("out", []byte(msg))
		_, err := conn.Write([]byte(msg))
		return err
	}
	if err := say("220 %s ESMTP Postfix (Ubuntu)", m.hostname); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := r.ReadString('\n')
		if err != nil {
			return nil
		}
		line = strings.TrimRight(line, "\r\n")
		s.Record("in", []byte(line))

		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(strings.TrimSpace(verb))
		arg = strings.TrimSpace(arg)

		switch verb {
		case "EHLO", "HELO":
			st.helo = arg
			if verb == "HELO" {
				if err := say("250 %s", m.hostname); err != nil {
					return err
				}
				continue
			}
			if err := say("250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME",
				m.hostname); err != nil {
				return err
			}

		case "AUTH":
			if err := m.auth(conn, r, s, st, arg, say); err != nil {
				return err
			}

		case "MAIL":
			st.from = extractAddress(arg)
			st.recipients = nil
			if err := say("250 2.1.0 Ok"); err != nil {
				return err
			}

		case "RCPT":
			to := extractAddress(arg)
			st.recipients = append(st.recipients, to)
			// A recipient outside our own domain, from an unauthenticated
			// sender, is an open-relay probe: one of the oldest automated
			// abuses there is, and still constant.
			if !strings.HasSuffix(strings.ToLower(to), "@"+strings.ToLower(m.p.Domain)) {
				e := s.Event(event.ClassDetectionFinding, 1, event.SeverityHigh).
					WithMessage("open relay probe: %s -> %s", st.from, to).
					WithAttack(event.Technique{Tactic: "TA0043", Technique: "T1595", Name: "Active Scanning"})
				e.Set("mail_from", st.from).Set("rcpt_to", to).Set("helo", st.helo).
					Set("auth_attempted_as", st.offeredUser).
					Set("relayed", false).Set("reason", "containment: decoys never deliver mail")
				s.Emit(e)
			}
			if err := say("250 2.1.5 Ok"); err != nil {
				return err
			}

		case "DATA":
			if err := say("354 End data with <CR><LF>.<CR><LF>"); err != nil {
				return err
			}
			body := readDotTerminated(r, s)
			e := s.Event(event.ClassDecoyInteraction, 1, event.SeverityHigh).
				WithMessage("message captured but not delivered: %s -> %v (%d bytes)",
					st.from, st.recipients, len(body))
			e.Set("mail_from", st.from).Set("rcpt_to", st.recipients).Set("helo", st.helo).
				Set("message", truncate(body, 65536)).Set("delivered", false)
			s.Emit(e)
			if err := say("250 2.0.0 Ok: queued as %s", strings.ToUpper(m.p.RandomToken(10))); err != nil {
				return err
			}

		case "RSET":
			st.from, st.recipients = "", nil
			if err := say("250 2.0.0 Ok"); err != nil {
				return err
			}

		case "VRFY", "EXPN":
			// User enumeration. Real Postfix refuses; so do we, and we record it.
			s.Command("smtp: "+line, event.SeverityMedium,
				event.Technique{Tactic: "TA0007", Technique: "T1087", Name: "Account Discovery"})
			if err := say("252 2.0.0 Cannot VRFY user"); err != nil {
				return err
			}

		case "NOOP":
			if err := say("250 2.0.0 Ok"); err != nil {
				return err
			}

		case "QUIT":
			say("221 2.0.0 Bye")
			return nil

		case "STARTTLS":
			if err := say("454 4.7.0 TLS not available due to temporary reason"); err != nil {
				return err
			}

		default:
			if err := say("502 5.5.2 Error: command not recognized"); err != nil {
				return err
			}
		}
	}
}

func (m *smtpSvc) auth(conn net.Conn, r *bufio.Reader, s *Session, st *smtpState, arg string,
	say func(string, ...any) error) error {

	mechanism, initial, _ := strings.Cut(arg, " ")
	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		payload := initial
		if payload == "" {
			if err := say("334 "); err != nil {
				return err
			}
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			payload = strings.TrimSpace(line)
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			parts := strings.Split(string(raw), "\x00")
			if len(parts) >= 3 {
				st.offeredUser = parts[1]
				s.AddCredential(Credential{Username: parts[1], Secret: parts[2], Method: "smtp-plain", Accepted: false})
			}
		}

	case "LOGIN":
		if err := say("334 VXNlcm5hbWU6"); err != nil { // "Username:"
			return err
		}
		userLine, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if err := say("334 UGFzc3dvcmQ6"); err != nil { // "Password:"
			return err
		}
		passLine, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		user, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(userLine))
		pass, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(passLine))
		st.offeredUser = string(user)
		s.AddCredential(Credential{
			Username: string(user), Secret: string(pass), Method: "smtp-login", Accepted: false,
		})

	default:
		return say("504 5.5.4 Unrecognized authentication type")
	}

	// Always refuse: an authenticated sender would expect to be able to send.
	time.Sleep(800 * time.Millisecond)
	return say("535 5.7.8 Error: authentication failed")
}

// readDotTerminated reads a DATA body, bounded so a spammer cannot exhaust us.
func readDotTerminated(r *bufio.Reader, s *Session) string {
	var b strings.Builder
	for b.Len() < 1<<20 {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimRight(line, "\r\n") == "." {
			break
		}
		b.WriteString(line)
	}
	s.Record("in", []byte(b.String()))
	return b.String()
}

func extractAddress(arg string) string {
	if i := strings.Index(arg, "<"); i >= 0 {
		if j := strings.Index(arg[i:], ">"); j > 0 {
			return arg[i+1 : i+j]
		}
	}
	if _, rest, ok := strings.Cut(arg, ":"); ok {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(arg)
}
