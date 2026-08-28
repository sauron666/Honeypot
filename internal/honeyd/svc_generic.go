package honeyd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("generic", newGeneric) }

// genericSvc answers any TCP port with an optional banner and records whatever
// arrives. It exists so that a decoy can present a realistic port profile
// without a bespoke implementation for every protocol, and so that unknown
// probes -- often the interesting ones -- are captured rather than refused.
type genericSvc struct {
	p       *Persona
	banner  string
	svcName string
	maxRead int
}

func newGeneric(p *Persona, opts map[string]any) (Service, error) {
	g := &genericSvc{p: p, svcName: "generic", maxRead: 64 * 1024}
	if v, ok := opts["banner"].(string); ok {
		g.banner = v
	}
	if v, ok := opts["name"].(string); ok && v != "" {
		g.svcName = v
	}
	return g, nil
}

func (g *genericSvc) Type() string { return "generic" }

func (g *genericSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	if g.banner != "" {
		msg := strings.ReplaceAll(g.banner, "\\r\\n", "\r\n")
		s.Record("out", []byte(msg))
		if _, err := conn.Write([]byte(msg)); err != nil {
			return err
		}
	}

	buf := make([]byte, 8192)
	total := 0
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)

	for total < g.maxRead {
		n, err := conn.Read(buf)
		if n > 0 {
			total += n
			chunk := buf[:n]
			s.Record("in", chunk)

			e := s.Event(event.ClassDecoyInteraction, 1, event.SeverityMedium).
				WithMessage("payload on %s/%d (%d bytes)", g.svcName, s.LocalPort(), n)
			sum := sha256.Sum256(chunk)
			e.Set("bytes", n).
				Set("payload_ascii", printableOnly(chunk)).
				Set("payload_hex", hex.EncodeToString(chunk[:min(n, 512)])).
				Set("sha256", hex.EncodeToString(sum[:]))
			s.Emit(e)
		}
		if err != nil {
			break
		}
	}

	if total == 0 {
		// A connect that sends nothing is a port scan, and saying so plainly is
		// more useful than an empty session record.
		s.Emit(s.Event(event.ClassDecoyInteraction, 2, event.SeverityLow).
			WithMessage("port scan: connected to %s/%d and sent nothing", g.svcName, s.LocalPort()).
			WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1046", Name: "Network Service Discovery"}))
	}
	return nil
}

func printableOnly(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte('.')
		}
		if sb.Len() > 2048 {
			sb.WriteString("...")
			break
		}
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
