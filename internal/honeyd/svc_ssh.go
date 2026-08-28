package honeyd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("ssh", newSSH) }

// sshSvc is a real SSH server that lets attackers in and watches what they do.
//
// It runs the genuine protocol (golang.org/x/crypto/ssh), not an approximation,
// so the handshake, key exchange and cipher negotiation are indistinguishable
// from a real server. What differs is what happens after authentication: the
// shell is the virtual one in shell.go, backed by the persona's in-memory
// filesystem, and nothing an attacker types is ever executed.
type sshSvc struct {
	p           *Persona
	config      *ssh.ServerConfig
	hostKeyPath string
	maxAuth     int

	mu       sync.Mutex
	attempts map[string]int // per-source authentication attempt counter
}

func newSSH(p *Persona, opts map[string]any) (Service, error) {
	s := &sshSvc{p: p, maxAuth: 6, attempts: map[string]int{}}
	if v, ok := opts["max_auth_tries"].(int); ok && v > 0 {
		s.maxAuth = v
	}
	if v, ok := opts["host_key_path"].(string); ok && v != "" {
		s.hostKeyPath = v
	} else {
		s.hostKeyPath = filepath.Join(os.TempDir(), "mirage-hostkeys")
	}

	cfg := &ssh.ServerConfig{
		// The version string is a fingerprint. It must match the persona's OS,
		// and it must never be a value a honeypot detector has seen before.
		ServerVersion: p.SSHBanner,
		MaxAuthTries:  s.maxAuth,
	}
	if err := s.loadHostKeys(cfg); err != nil {
		return nil, err
	}
	s.config = cfg
	return s, nil
}

func (s *sshSvc) Type() string { return "ssh" }

// loadHostKeys loads or creates persistent host keys. Persistence is a security
// property here, not a convenience: a host key that changes on every restart is
// an unmistakable sign of a honeypot, and it makes clients shout at the user.
func (s *sshSvc) loadHostKeys(cfg *ssh.ServerConfig) error {
	if err := os.MkdirAll(s.hostKeyPath, 0o700); err != nil {
		return fmt.Errorf("ssh: host key directory: %w", err)
	}
	// OpenSSH offers both, and so must we.
	edSigner, err := s.loadOrCreate("ssh_host_ed25519_key", genEd25519)
	if err != nil {
		return err
	}
	cfg.AddHostKey(edSigner)

	rsaSigner, err := s.loadOrCreate("ssh_host_rsa_key", genRSA)
	if err != nil {
		return err
	}
	cfg.AddHostKey(rsaSigner)
	return nil
}

func (s *sshSvc) loadOrCreate(name string, gen func() ([]byte, error)) (ssh.Signer, error) {
	path := filepath.Join(s.hostKeyPath, s.p.Hostname+"_"+name)
	pemBytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		pemBytes, err = gen()
		if err != nil {
			return nil, fmt.Errorf("ssh: generate %s: %w", name, err)
		}
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			return nil, fmt.Errorf("ssh: persist %s: %w", name, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("ssh: read %s: %w", name, err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse %s: %w", name, err)
	}
	return signer, nil
}

func genEd25519() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func genRSA() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}

func (s *sshSvc) nextAttempt(src string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[src]++
	// Bound the map so a spray across many sources cannot grow it forever.
	if len(s.attempts) > 10000 {
		s.attempts = map[string]int{src: s.attempts[src]}
	}
	return s.attempts[src]
}

func (s *sshSvc) Serve(ctx context.Context, conn net.Conn, sess *Session) error {
	// Per-connection config so that auth callbacks can reach this session.
	cfg := *s.config
	var authedUser string

	cfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		attempt := s.nextAttempt(sess.SrcIP())
		user := c.User()
		accepted := s.p.Accepts(user, string(pass), attempt)
		sess.AddCredential(Credential{
			Username: user, Secret: string(pass), Method: "password", Accepted: accepted,
		})
		if accepted {
			authedUser = user
			return &ssh.Permissions{Extensions: map[string]string{"user": user}}, nil
		}
		// Real sshd delays failed passwords. Answering instantly is a tell.
		time.Sleep(time.Duration(400+len(pass)*7) * time.Millisecond)
		return nil, fmt.Errorf("permission denied")
	}

	cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Public keys are never accepted -- accepting one would mean an
		// attacker could return silently -- but the fingerprint is recorded,
		// and it is one of the most durable identifiers an actor carries.
		sess.AddCredential(Credential{
			Username: c.User(), Method: "publickey", Accepted: false,
			KeyType: key.Type(), KeyPrint: ssh.FingerprintSHA256(key),
		})
		return nil, fmt.Errorf("permission denied")
	}

	cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := chal("", "", []string{"Password: "}, []bool{false})
		if err != nil || len(answers) == 0 {
			return nil, fmt.Errorf("permission denied")
		}
		attempt := s.nextAttempt(sess.SrcIP())
		accepted := s.p.Accepts(c.User(), answers[0], attempt)
		sess.AddCredential(Credential{
			Username: c.User(), Secret: answers[0], Method: "keyboard-interactive", Accepted: accepted,
		})
		if accepted {
			authedUser = c.User()
			return &ssh.Permissions{Extensions: map[string]string{"user": c.User()}}, nil
		}
		time.Sleep(500 * time.Millisecond)
		return nil, fmt.Errorf("permission denied")
	}

	sconn, chans, reqs, err := ssh.NewServerConn(conn, &cfg)
	if err != nil {
		// A failed handshake is still information: the client version tells us
		// which tool was used even when authentication never succeeded.
		return fmt.Errorf("handshake: %w", err)
	}
	defer sconn.Close()

	clientVersion := string(sconn.ClientVersion())
	e := sess.Event(event.ClassAuthentication, 1, event.SeverityHigh).
		WithMessage("SSH login accepted for %q from %s", authedUser, clientVersion).
		WithAttack(event.Technique{Tactic: "TA0001", Technique: "T1078", Name: "Valid Accounts"})
	e.Actor.User = authedUser
	e.Set("client_version", clientVersion).
		Set("username", authedUser).
		Set("session_id", sess.ID).
		Set("client_tool", classifySSHClient(clientVersion))
	sess.Emit(e)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return err
		}
		go s.handleChannel(ctx, ch, chReqs, sess, authedUser)
	}
	return nil
}

// handleChannel services one SSH session channel.
func (s *sshSvc) handleChannel(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, sess *Session, user string) {
	defer ch.Close()
	sh := NewShell(s.p, sess, user)
	interactive := false

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			interactive = true
			req.Reply(true, nil)

		case "env":
			req.Reply(true, nil)

		case "window-change":
			req.Reply(true, nil)

		case "shell":
			req.Reply(true, nil)
			s.interactiveShell(ctx, ch, sh, sess)
			ch.SendRequest("exit-status", false, exitStatus(0))
			return

		case "exec":
			// A one-shot command: the most common way automated attacks use
			// SSH, and the payload is right there in the request.
			cmd := parseExecPayload(req.Payload)
			req.Reply(true, nil)
			sess.Record("in", []byte(cmd))
			out, _ := sh.Execute(cmd)
			if out != "" {
				ch.Write([]byte(out))
				sess.Record("out", []byte(out))
			}
			ch.SendRequest("exit-status", false, exitStatus(0))
			return

		case "subsystem":
			name := parseExecPayload(req.Payload)
			sess.Note(event.SeverityMedium, "SSH subsystem requested: %s", name)
			// SFTP is the usual request. Refusing it is honest: we do not
			// implement the protocol, and a broken half-implementation would be
			// far more detectable than a clean refusal.
			req.Reply(false, nil)

		default:
			req.Reply(false, nil)
		}
	}
	_ = interactive
}

// interactiveShell runs the line-edited terminal loop.
func (s *sshSvc) interactiveShell(ctx context.Context, ch ssh.Channel, sh *Shell, sess *Session) {
	write := func(str string) {
		ch.Write([]byte(strings.ReplaceAll(str, "\n", "\r\n")))
	}
	write(sh.Banner())

	var line []rune
	buf := make([]byte, 1)
	write("\r\n" + sh.Prompt())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := ch.Read(buf)
		if err != nil || n == 0 {
			return
		}
		c := buf[0]
		switch c {
		case '\r', '\n':
			cmd := string(line)
			line = line[:0]
			write("\r\n")
			sess.Record("in", []byte(cmd))
			out, exit := sh.Execute(cmd)
			if out != "" {
				write(out)
				sess.Record("out", []byte(out))
				if !strings.HasSuffix(out, "\n") {
					write("\n")
				}
			}
			if exit {
				return
			}
			write(sh.Prompt())

		case 0x03: // Ctrl-C
			line = line[:0]
			write("^C\r\n" + sh.Prompt())

		case 0x04: // Ctrl-D
			write("logout\r\n")
			return

		case 0x7f, 0x08: // backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				write("\b \b")
			}

		case '\t':
			// Real bash would complete; silence is closer than a wrong guess.

		default:
			if c >= 0x20 && c < 0x7f {
				line = append(line, rune(c))
				ch.Write([]byte{c})
				if len(line) > 8192 {
					line = line[:0]
					write("\r\n-bash: line too long\r\n" + sh.Prompt())
				}
			}
		}
	}
}

// parseExecPayload extracts the command from an exec/subsystem request payload,
// which is a 4-byte big-endian length followed by the string.
func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || n > len(payload)-4 {
		return string(payload[4:])
	}
	return string(payload[4 : 4+n])
}

func exitStatus(code uint32) []byte {
	return []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code)}
}

// classifySSHClient turns a client version string into a tool name. Attackers
// change IPs constantly; their tooling changes far less often.
func classifySSHClient(v string) string {
	l := strings.ToLower(v)
	switch {
	case strings.Contains(l, "paramiko"):
		return "paramiko (python automation)"
	case strings.Contains(l, "libssh"):
		return "libssh (automation or exploit tooling)"
	case strings.Contains(l, "go"):
		return "go x/crypto (custom tooling)"
	case strings.Contains(l, "putty"):
		return "putty"
	case strings.Contains(l, "jsch"):
		return "jsch (java)"
	case strings.Contains(l, "russh"), strings.Contains(l, "rust"):
		return "rust ssh client"
	case strings.Contains(l, "openssh"):
		return "openssh"
	case strings.Contains(l, "zgrab"), strings.Contains(l, "scan"):
		return "internet-wide scanner"
	default:
		return "unknown"
	}
}
