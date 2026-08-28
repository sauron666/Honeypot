package presence

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// issue builds a throwaway CA and returns the directory holding it.
func issue(t *testing.T, agents ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pki")
	if _, err := (PKI{Dir: dir, Hosts: []string{"127.0.0.1", "hub.example"},
		Agents: agents, Validity: time.Hour}).Generate(); err != nil {
		t.Fatalf("issue: %v", err)
	}
	return dir
}

func hubTLS(dir string, mutual bool) TLSConfig {
	c := TLSConfig{
		CertFile: filepath.Join(dir, "hub.crt"),
		KeyFile:  filepath.Join(dir, "hub.key"),
	}
	if mutual {
		c.CAFile = filepath.Join(dir, "ca.crt")
	}
	return c
}

func agentTLS(dir, id string, withCert bool) TLSConfig {
	c := TLSConfig{
		CAFile:     filepath.Join(dir, "ca.crt"),
		ServerName: "127.0.0.1",
	}
	if withCert {
		c.CertFile = filepath.Join(dir, "agent-"+safeName(id)+".crt")
		c.KeyFile = filepath.Join(dir, "agent-"+safeName(id)+".key")
	}
	return c
}

// tlsOverlay is the overlay helper with TLS on both ends.
func tlsOverlay(t *testing.T, hubCfg, agentCfg TLSConfig) (*echoHandler, *Agent) {
	t.Helper()
	h := &echoHandler{}
	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "hub-secret", TLS: hubCfg,
		Agents: []AgentConfig{{ID: "a", DecoyID: "d", Persona: "linux/web",
			Services: []string{"http"}}},
	}, h, quiet())
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := hub.Start(ctx); err != nil {
		t.Fatalf("hub start: %v", err)
	}
	t.Cleanup(func() { hub.Close() })

	agent, err := NewAgent(AgentSettings{
		Hub: hub.Addr(), Token: "hub-secret", ID: "a", TLS: agentCfg,
		Addresses:    []string{"127.0.0.1"},
		Services:     []ServiceBinding{{Service: "http", Port: freePort(t)}},
		ReconnectMin: 50 * time.Millisecond, ReconnectMax: 200 * time.Millisecond,
	}, quiet())
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	go agent.Run(ctx)
	t.Cleanup(func() { agent.Close() })
	return h, agent
}

func TestMutualTLSCarriesASession(t *testing.T) {
	dir := issue(t, "a")
	h, agent := tlsOverlay(t, hubTLS(dir, true), agentTLS(dir, "a", true))
	waitConnected(t, agent, true)

	conn, err := net.Dial("tcp", agent.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, "GET / HTTP/1.1\r\n\r\n")

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("nothing came back through the TLS tunnel: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "decoy saw: GET /") {
		t.Fatalf("the decoy's answer did not survive TLS: %q", buf[:n])
	}
	if calls := h.waitFor(t, 1); calls[0].service != "http" {
		t.Fatalf("wrong service attributed: %+v", calls[0])
	}
}

func TestHubWithAClientCARefusesAnAgentWithoutACertificate(t *testing.T) {
	// The token alone must not be enough once mutual TLS is configured: an
	// attacker who reads a token off a compromised agent should still not be
	// able to stand up an agent of their own.
	dir := issue(t, "a")
	_, agent := tlsOverlay(t, hubTLS(dir, true), agentTLS(dir, "a", false))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if agent.Connected() {
			t.Fatal("an agent with no client certificate was accepted")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAgentRefusesAHubWithAnUntrustedCertificate(t *testing.T) {
	// Two independent CAs: the hub's certificate is perfectly valid and signed
	// by nothing the agent trusts, which is what an interception looks like.
	hubDir := issue(t, "a")
	otherDir := issue(t, "a")
	_, agent := tlsOverlay(t, hubTLS(hubDir, false), agentTLS(otherDir, "a", true))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if agent.Connected() {
			t.Fatal("the agent trusted a hub certificate from an unrelated CA")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTokenIsStillRequiredOverTLS(t *testing.T) {
	// TLS authenticates the machine; the token authenticates the deployment.
	// A valid certificate with the wrong token must not get in.
	dir := issue(t, "a")
	h := &echoHandler{}
	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "hub-secret", TLS: hubTLS(dir, true),
		Agents: []AgentConfig{{ID: "a", DecoyID: "d", Persona: "linux/web",
			Services: []string{"http"}}},
	}, h, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := hub.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer hub.Close()

	agent, err := NewAgent(AgentSettings{
		Hub: hub.Addr(), Token: "wrong-secret", ID: "a", TLS: agentTLS(dir, "a", true),
		Addresses:    []string{"127.0.0.1"},
		Services:     []ServiceBinding{{Service: "http", Port: freePort(t)}},
		ReconnectMin: 50 * time.Millisecond, ReconnectMax: 200 * time.Millisecond,
	}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	defer agent.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if agent.Connected() {
			t.Fatal("a valid certificate with the wrong token was accepted")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTLSConfigRefusesContradictorySettings(t *testing.T) {
	_, err := TLSConfig{InsecureSkipVerify: true, CAFile: "ca.crt"}.ClientConfig()
	if err == nil {
		t.Fatal("insecure_skip_verify together with a CA should be refused")
	}
	if _, err := (TLSConfig{CertFile: "hub.crt"}).ServerConfig(); err == nil {
		t.Fatal("a hub certificate without its key should be refused")
	}
	if _, err := (TLSConfig{CertFile: "a.crt"}).ClientConfig(); err == nil {
		t.Fatal("an agent certificate without its key should be refused")
	}
	if (TLSConfig{}).Enabled() {
		t.Fatal("an empty TLS configuration is not enabled")
	}
}

func TestPKIIssuesUsableMaterial(t *testing.T) {
	dir := issue(t, "floor-3", "dmz/edge")

	for _, name := range []string{"ca.crt", "ca.key", "hub.crt", "hub.key",
		"agent-floor-3.crt", "agent-floor-3.key", "agent-dmz_edge.crt", "agent-dmz_edge.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not issued: %v", name, err)
		}
		if strings.HasSuffix(name, ".key") && info.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
			t.Fatalf("%s has mode %v; a private key must not be world readable", name, info.Mode().Perm())
		}
	}

	// The hub must be able to load what was issued for it, and the CA must
	// verify an agent certificate.
	if _, err := hubTLS(dir, true).ServerConfig(); err != nil {
		t.Fatalf("the hub cannot load its own material: %v", err)
	}
	if _, err := agentTLS(dir, "floor-3", true).ClientConfig(); err != nil {
		t.Fatalf("an agent cannot load its own material: %v", err)
	}

	// Re-issuing over live material would invalidate every deployed agent.
	if _, err := (PKI{Dir: dir, Hosts: []string{"127.0.0.1"}, Agents: []string{"a"}}).Generate(); err == nil {
		t.Fatal("Generate overwrote an existing CA")
	}
}

func TestPKIRejectsUselessRequests(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		name string
		pki  PKI
	}{
		{"no hosts", PKI{Dir: filepath.Join(base, "1"), Agents: []string{"a"}}},
		{"no agents", PKI{Dir: filepath.Join(base, "2"), Hosts: []string{"127.0.0.1"}}},
		{"no dir", PKI{Hosts: []string{"127.0.0.1"}, Agents: []string{"a"}}},
		{"duplicate agent", PKI{Dir: filepath.Join(base, "3"), Hosts: []string{"127.0.0.1"},
			Agents: []string{"a", "a"}}},
		{"empty agent id", PKI{Dir: filepath.Join(base, "4"), Hosts: []string{"127.0.0.1"},
			Agents: []string{" "}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.pki.Generate(); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestStreamReadHonoursItsDeadline(t *testing.T) {
	// Every emulated service sets a read deadline so an attacker who connects
	// and says nothing is eventually dropped. A stream that ignored them would
	// hold a goroutine and a stream id for as long as the attacker liked.
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	tun := newTunnel(left, true)
	defer tun.Close()

	s, err := tun.open(tunnelAddr{"tcp", "10.0.0.1:80"}, tunnelAddr{"tcp", "10.0.0.9:5555"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetReadDeadline(time.Now().Add(80 * time.Millisecond))

	start := time.Now()
	_, err = s.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read returned %v, want a deadline error", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatal("a service checking net.Error.Timeout would not recognise this")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the deadline took %v to fire", elapsed)
	}
}

func TestStreamReadPicksUpADeadlineSetWhileItWaits(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	tun := newTunnel(left, true)
	defer tun.Close()

	s, err := tun.open(tunnelAddr{"tcp", "10.0.0.1:80"}, tunnelAddr{"tcp", "10.0.0.9:5555"})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read returned %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a deadline set during a blocked Read never took effect")
	}
}

func TestStreamDeliversQueuedBytesBeforeEOF(t *testing.T) {
	// The peer routinely answers and closes in the same breath; losing the
	// answer to the close would turn every short session into an empty one.
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	tun := newTunnel(left, true)
	defer tun.Close()

	s, err := tun.open(tunnelAddr{"tcp", "10.0.0.1:80"}, tunnelAddr{"tcp", "10.0.0.9:5555"})
	if err != nil {
		t.Fatal(err)
	}
	s.deliver([]byte("220 mail.example ESMTP"))
	s.closeLocal()

	buf := make([]byte, 64)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("the queued answer was lost: %v", err)
	}
	if string(buf[:n]) != "220 mail.example ESMTP" {
		t.Fatalf("got %q", buf[:n])
	}
	if _, err := s.Read(buf); err == nil {
		t.Fatal("the stream should report EOF once drained")
	}
}
