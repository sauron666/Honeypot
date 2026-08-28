package honeyd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("vnc", newVNC) }

// vncSvc emulates an RFB server offering VNC authentication.
//
// VNC auth is a DES challenge-response over an eight character password. The
// decoy chooses the challenge, so challenge plus response is directly
// crackable: an exposed VNC server is a favourite of both ransomware crews and
// commodity scanners, and this records exactly what they tried.
type vncSvc struct {
	p       *Persona
	version string
}

func newVNC(p *Persona, opts map[string]any) (Service, error) {
	v := &vncSvc{p: p, version: "RFB 003.008\n"}
	if s, ok := opts["version"].(string); ok && s != "" {
		v.version = s
	}
	return v, nil
}

func (v *vncSvc) Type() string { return "vnc" }

func (v *vncSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)

	if _, err := conn.Write([]byte(v.version)); err != nil {
		return err
	}
	clientVer := make([]byte, 12)
	if _, err := io.ReadFull(r, clientVer); err != nil {
		return err
	}
	s.Record("in", clientVer)

	// Offer exactly one security type: VNC authentication.
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		return err
	}
	choice := make([]byte, 1)
	if _, err := io.ReadFull(r, choice); err != nil {
		return err
	}
	if choice[0] != 2 {
		s.Note(event.SeverityLow, "VNC client requested security type %d, not VNC auth", choice[0])
		return nil
	}

	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if _, err := conn.Write(challenge); err != nil {
		return err
	}

	response := make([]byte, 16)
	if _, err := io.ReadFull(r, response); err != nil {
		return err
	}
	s.Record("in", response)

	s.AddCredential(Credential{
		Username: "", Method: "vnc-des-challenge", Accepted: false,
		KeyType:  "vnc-challenge-response",
		KeyPrint: hex.EncodeToString(challenge) + ":" + hex.EncodeToString(response),
	})

	e := s.Event(event.ClassAuthentication, 1, event.SeverityHigh).
		WithMessage("VNC authentication attempt from client %q", string(clientVer[:11])).
		WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1110", Name: "Brute Force"})
	e.Set("client_version", string(clientVer[:11])).
		Set("challenge_hex", hex.EncodeToString(challenge)).
		Set("response_hex", hex.EncodeToString(response)).
		Set("crackable", "vnc des: 8-character password over the recorded challenge")
	s.Emit(e)

	// Fail the authentication: a working VNC desktop is not something a decoy
	// can fake convincingly, and a bad frame buffer is more revealing than a
	// refused password.
	fail := make([]byte, 4)
	binary.BigEndian.PutUint32(fail, 1)
	conn.Write(fail)
	reason := "Authentication failed"
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(reason)))
	conn.Write(append(buf, reason...))
	return nil
}
