package honeyd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("tokens", newTokenReceiver) }

// TokenLookup resolves a honeytoken id and records the trigger. It is supplied
// by the control plane through service options, so that this package stays
// ignorant of how tokens are stored.
//
// The returned label, kind and location are what turn a bare trigger into an
// investigation: "the AWS key from the finance file share was just used".
type TokenLookup func(id string) (label, kind, location string, ok bool)

// tokenReceiver answers honeytoken callbacks.
//
// It is a decoy service like any other rather than part of the management API,
// because it must be reachable by whoever found the token -- and the management
// API must not be (docs/04).
type tokenReceiver struct {
	p      *Persona
	lookup TokenLookup
}

func newTokenReceiver(p *Persona, opts map[string]any) (Service, error) {
	lookup, _ := opts["lookup"].(TokenLookup)
	if lookup == nil {
		return nil, fmt.Errorf("honeyd: the tokens service needs a lookup function")
	}
	return &tokenReceiver{p: p, lookup: lookup}, nil
}

func (t *tokenReceiver) Type() string { return "tokens" }

// A 1x1 transparent GIF: small, universally rendered, and unremarkable in a
// document or a web page.
var pixelGIF, _ = base64.StdEncoding.DecodeString(
	"R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

func (t *tokenReceiver) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	br := bufio.NewReader(io.LimitReader(conn, 1<<20))

	for i := 0; i < 16; i++ {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil
		}
		if req.Body != nil {
			io.Copy(io.Discard, io.LimitReader(req.Body, 65536))
			req.Body.Close()
		}
		s.Record("in", []byte(req.Method+" "+req.URL.RequestURI()))

		id := tokenIDFromPath(req.URL.Path)
		if id == "" {
			t.writeSimple(conn, "404 Not Found", "text/plain", []byte("Not Found\n"))
			continue
		}

		label, kind, location, ok := t.lookup(id)
		if !ok {
			// An unknown token id is still interesting: someone is guessing, or
			// replaying a token from another deployment.
			e := s.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
				WithMessage("callback for an unknown honeytoken id %q", id)
			e.Set("token_id", id).Set("user_agent", req.UserAgent())
			s.Emit(e)
			t.writeSimple(conn, "404 Not Found", "text/plain", []byte("Not Found\n"))
			continue
		}

		e := s.Event(event.ClassTokenTriggered, 1, event.SeverityCritical).
			WithMessage("honeytoken %q triggered (%s) from %s", label, kind, s.SrcIP()).
			WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1552", Name: "Unsecured Credentials"})
		e.Set("token_id", id).
			Set("token_label", label).
			Set("token_type", kind).
			Set("token_location", location).
			Set("trigger_method", "callback").
			Set("user_agent", req.UserAgent()).
			Set("request_path", req.URL.Path).
			Set("referer", req.Referer())
		s.Emit(e)

		// Answer with something innocuous, so whoever opened the document or
		// followed the link sees nothing unusual.
		t.writeSimple(conn, "200 OK", "image/gif", pixelGIF)
	}
	return nil
}

// tokenIDFromPath extracts the id from /t/<id>[/anything].
func tokenIDFromPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 2 || parts[0] != "t" {
		return ""
	}
	id := parts[1]
	if len(id) < 4 || len(id) > 64 {
		return ""
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return ""
		}
	}
	return id
}

func (t *tokenReceiver) writeSimple(w net.Conn, status, contentType string, body []byte) {
	// The Server header is a fingerprint. A bare "nginx" beside a web decoy that
	// answers "nginx/1.22.1" on the same estate is a tell -- one machine running
	// two nginx versions -- so mirror the persona's advertised server, with a
	// versioned fallback for personas that carry no HTTP identity.
	server := t.p.HTTPServer
	if server == "" {
		server = "nginx/1.22.1"
	}
	fmt.Fprintf(w, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\n"+
		"Content-Length: %d\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n",
		status, time.Now().UTC().Format(http.TimeFormat), server, contentType, len(body))
	w.Write(body)
}
