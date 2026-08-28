package presence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoHandler stands in for the decoy farm: it records what it was told about
// each tunnelled connection and echoes whatever arrives.
type echoHandler struct {
	mu    sync.Mutex
	calls []handled
}

type handled struct {
	service, persona, decoyID string
	remote                    string
	received                  string
}

func (h *echoHandler) ServeConn(ctx context.Context, conn net.Conn,
	service, persona, decoyID string, remote net.Addr) error {

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	got := string(buf[:n])
	conn.Write([]byte("decoy saw: " + got))

	h.mu.Lock()
	h.calls = append(h.calls, handled{
		service: service, persona: persona, decoyID: decoyID,
		remote: remote.String(), received: got,
	})
	h.mu.Unlock()
	return nil
}

func (h *echoHandler) all() []handled {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]handled(nil), h.calls...)
}

func (h *echoHandler) waitFor(t *testing.T, n int) []handled {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := h.all(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only %d of %d tunnelled sessions reached the handler", len(h.all()), n)
	return nil
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// freePort asks the kernel for an unused port and gives it straight back.
//
// The agent deliberately refuses port 0: a decoy has to claim the port an
// attacker expects to find, so "let the kernel pick" is never right in a real
// deployment. Tests therefore pick a concrete free port instead.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// overlay starts a hub and an agent wired to each other.
func overlay(t *testing.T, agentCfg AgentConfig, claims []ServiceBinding, token string) (*echoHandler, *Agent) {
	t.Helper()
	h := &echoHandler{}

	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "hub-secret", Agents: []AgentConfig{agentCfg},
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
		Hub: hub.Addr(), Token: token, ID: agentCfg.ID,
		Addresses: []string{"127.0.0.1"}, Services: claims,
		ReconnectMin: 50 * time.Millisecond, ReconnectMax: 200 * time.Millisecond,
	}, quiet())
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	go agent.Run(ctx)
	t.Cleanup(func() { agent.Close() })
	return h, agent
}

func waitConnected(t *testing.T, a *Agent, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Connected() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent connected = %v, want %v", a.Connected(), want)
}

func TestOverlayCarriesAConnectionAndKeepsTheRealSourceAddress(t *testing.T) {
	h, agent := overlay(t,
		AgentConfig{ID: "floor-3", DecoyID: "dcy-remote01", Persona: "linux/web",
			Services: []string{"http"}},
		[]ServiceBinding{{Service: "http", Port: freePort(t)}},
		"hub-secret")
	waitConnected(t, agent, true)

	addrs := agent.Addrs()
	if len(addrs) != 1 {
		t.Fatalf("agent claimed %d endpoints", len(addrs))
	}

	conn, err := net.Dial("tcp", addrs[0])
	if err != nil {
		t.Fatalf("dial the claimed address: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, "GET / HTTP/1.1\r\n\r\n")

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer came back through the tunnel: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "decoy saw: GET /") {
		t.Fatalf("the decoy's answer did not arrive intact: %q", buf[:n])
	}

	calls := h.waitFor(t, 1)
	got := calls[0]
	if got.service != "http" || got.persona != "linux/web" || got.decoyID != "dcy-remote01" {
		t.Fatalf("the hub described the session wrongly: %+v", got)
	}

	// This is the point of the whole design: the decoy must see the attacker,
	// not the agent. Attributing every tunnelled session to the agent would
	// merge every attacker in a segment into one meaningless engagement.
	localHost, localPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	remoteHost, remotePort, _ := net.SplitHostPort(got.remote)
	if remoteHost != localHost || remotePort != localPort {
		t.Fatalf("the decoy saw %s but the client was %s", got.remote, conn.LocalAddr())
	}
}

func TestHubRejectsABadToken(t *testing.T) {
	// The token is the only thing between an attacker on the segment and the
	// ability to project decoys of their own into the platform.
	_, agent := overlay(t,
		AgentConfig{ID: "floor-3", DecoyID: "d", Persona: "linux/web", Services: []string{"http"}},
		[]ServiceBinding{{Service: "http", Port: freePort(t)}},
		"wrong-token")

	time.Sleep(600 * time.Millisecond)
	if agent.Connected() {
		t.Fatal("an agent with the wrong token was accepted")
	}
}

func TestHubRejectsAnUnknownAgent(t *testing.T) {
	h := &echoHandler{}
	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "hub-secret",
		Agents: []AgentConfig{{ID: "known", DecoyID: "d", Persona: "linux/web", Services: []string{"http"}}},
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
		Hub: hub.Addr(), Token: "hub-secret", ID: "stranger",
		Addresses: []string{"127.0.0.1"}, Services: []ServiceBinding{{Service: "http", Port: freePort(t)}},
		ReconnectMin: 50 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
	}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	defer agent.Close()

	time.Sleep(500 * time.Millisecond)
	if agent.Connected() {
		t.Fatal("an agent the hub does not know was accepted")
	}
}

func TestHubRefusesToCarryAnUndeclaredService(t *testing.T) {
	// The hub decides what an agent may forward, not the agent: an agent sits
	// in someone else's segment and must be assumed compromisable.
	h, agent := overlay(t,
		AgentConfig{ID: "floor-3", DecoyID: "d", Persona: "linux/web",
			Services: []string{"http"}}, // the hub permits only http
		[]ServiceBinding{{Service: "http", Port: freePort(t)}, {Service: "ssh", Port: freePort(t)}},
		"hub-secret")
	waitConnected(t, agent, true)

	addrs := agent.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("agent claimed %d endpoints", len(addrs))
	}
	// The second binding is ssh, which the hub did not declare.
	conn, err := net.Dial("tcp", addrs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "SSH-2.0-attacker\r\n")

	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		t.Fatalf("an undeclared service was carried: %q", buf[:n])
	}
	time.Sleep(300 * time.Millisecond)
	for _, c := range h.all() {
		if c.service == "ssh" {
			t.Fatal("the handler was asked to serve a service the hub never declared")
		}
	}
}

func TestAgentFailsClosedWhenTheTunnelIsDown(t *testing.T) {
	// A decoy that answers while nothing is recording is worse than a closed
	// port: it invites an attacker to spend time somewhere we learn nothing.
	h := &echoHandler{}
	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "hub-secret",
		Agents: []AgentConfig{{ID: "a", DecoyID: "d", Persona: "linux/web", Services: []string{"http"}}},
	}, h, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub.Start(ctx)

	agent, err := NewAgent(AgentSettings{
		Hub: hub.Addr(), Token: "hub-secret", ID: "a",
		Addresses: []string{"127.0.0.1"}, Services: []ServiceBinding{{Service: "http", Port: freePort(t)}},
		ReconnectMin: 20 * time.Second, ReconnectMax: 20 * time.Second,
	}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	defer agent.Close()
	waitConnected(t, agent, true)

	// Take the hub away; the claimed address stays bound.
	hub.Close()
	waitConnected(t, agent, false)

	conn, err := net.Dial("tcp", agent.Addrs()[0])
	if err != nil {
		t.Fatalf("the claimed address should still accept: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "hello?")

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("the agent answered with no tunnel: %q", buf[:n])
	}
	if !errors.Is(err, io.EOF) && err != nil && !strings.Contains(err.Error(), "reset") {
		t.Logf("connection ended with %v, which is fine as long as nothing was served", err)
	}
	if len(h.all()) != 0 {
		t.Fatal("something reached the handler with the tunnel down")
	}
}

func TestConcurrentStreamsDoNotCross(t *testing.T) {
	h, agent := overlay(t,
		AgentConfig{ID: "a", DecoyID: "d", Persona: "linux/web", Services: []string{"http"}},
		[]ServiceBinding{{Service: "http", Port: freePort(t)}},
		"hub-secret")
	waitConnected(t, agent, true)
	addr := agent.Addrs()[0]

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				errs[i] = err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			payload := fmt.Sprintf("request-%02d", i)
			fmt.Fprint(conn, payload)

			buf := make([]byte, 256)
			read, err := conn.Read(buf)
			if err != nil {
				errs[i] = err
				return
			}
			// Each stream must get its own answer back, not another's.
			if want := "decoy saw: " + payload; string(buf[:read]) != want {
				errs[i] = fmt.Errorf("stream %d got %q, want %q", i, buf[:read], want)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("stream %d: %v", i, err)
		}
	}
	h.waitFor(t, n)
}

func TestLargePayloadSurvivesFraming(t *testing.T) {
	// A payload larger than one frame must arrive whole, in order.
	h := &echoHandler{}
	hub, err := NewHub(HubConfig{
		Listen: "127.0.0.1:0", Token: "t",
		Agents: []AgentConfig{{ID: "a", DecoyID: "d", Persona: "linux/web", Services: []string{"http"}}},
	}, &sinkHandler{inner: h}, quiet())
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
		Hub: hub.Addr(), Token: "t", ID: "a",
		Addresses: []string{"127.0.0.1"}, Services: []ServiceBinding{{Service: "http", Port: freePort(t)}},
		ReconnectMin: 20 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
	}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	defer agent.Close()
	waitConnected(t, agent, true)

	conn, err := net.Dial("tcp", agent.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := bytes.Repeat([]byte("MIRAGE-OVERLAY-"), 20000) // ~300 KB
	go func() {
		conn.Write(payload)
	}()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 32*1024)
	for len(got) < len(payload) {
		n, err := conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted through the tunnel: got %d of %d bytes", len(got), len(payload))
	}
}

// sinkHandler echoes everything it receives, for the large-payload test.
type sinkHandler struct{ inner *echoHandler }

func (s *sinkHandler) ServeConn(ctx context.Context, conn net.Conn,
	service, persona, decoyID string, remote net.Addr) error {
	io.Copy(conn, conn)
	return nil
}

func TestFrameCodecRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Frame{Type: FrameData, Stream: 4242, Payload: []byte("hello overlay")}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != in.Type || out.Stream != in.Stream || string(out.Payload) != string(in.Payload) {
		t.Fatalf("round trip changed the frame: %+v vs %+v", out, in)
	}
}

func TestFrameCodecRejectsOversizedInput(t *testing.T) {
	// A tunnel carries attacker-controlled traffic; an unbounded length field
	// is an allocation primitive.
	if err := WriteFrame(io.Discard, Frame{Payload: make([]byte, MaxFrameSize+1)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writing an oversized frame returned %v", err)
	}
	hdr := []byte{FrameData, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}
	if _, err := ReadFrame(bytes.NewReader(hdr)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("reading an oversized length returned %v", err)
	}
}

func TestHubConfigurationIsValidated(t *testing.T) {
	h := &echoHandler{}
	cases := []struct {
		name string
		cfg  HubConfig
		want string
	}{
		{"no listen", HubConfig{Token: "t", Agents: []AgentConfig{{ID: "a", Persona: "p", Services: []string{"http"}}}}, "listen address"},
		{"no token", HubConfig{Listen: ":0", Agents: []AgentConfig{{ID: "a", Persona: "p", Services: []string{"http"}}}}, "token is required"},
		{"no agents", HubConfig{Listen: ":0", Token: "t"}, "no agents"},
		{"agent without persona", HubConfig{Listen: ":0", Token: "t", Agents: []AgentConfig{{ID: "a", Services: []string{"http"}}}}, "no persona"},
		{"agent forwards nothing", HubConfig{Listen: ":0", Token: "t", Agents: []AgentConfig{{ID: "a", Persona: "p"}}}, "may forward nothing"},
		{"duplicate agent", HubConfig{Listen: ":0", Token: "t", Agents: []AgentConfig{
			{ID: "a", Persona: "p", Services: []string{"http"}},
			{ID: "a", Persona: "p", Services: []string{"http"}},
		}}, "duplicate agent id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHub(tc.cfg, h, quiet())
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestAgentSettingsAreValidated(t *testing.T) {
	cases := []struct {
		name string
		set  AgentSettings
		want string
	}{
		{"no hub", AgentSettings{Token: "t", ID: "a", Services: []ServiceBinding{{Service: "http", Port: 80}}}, "hub address"},
		{"no token", AgentSettings{Hub: "h:1", ID: "a", Services: []ServiceBinding{{Service: "http", Port: 80}}}, "token is required"},
		{"no id", AgentSettings{Hub: "h:1", Token: "t", Services: []ServiceBinding{{Service: "http", Port: 80}}}, "agent id"},
		{"no services", AgentSettings{Hub: "h:1", Token: "t", ID: "a"}, "claim nothing"},
		{"port zero", AgentSettings{Hub: "h:1", Token: "t", ID: "a", Services: []ServiceBinding{{Service: "http", Port: 0}}}, "invalid port"},
		{"bad address", AgentSettings{Hub: "h:1", Token: "t", ID: "a", Addresses: []string{"nope"},
			Services: []ServiceBinding{{Service: "http", Port: 80}}}, "not a valid address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}
