package presence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ServiceBinding is one address and port the agent claims.
type ServiceBinding struct {
	Service string `yaml:"service" json:"service"`
	Port    int    `yaml:"port" json:"port"`
}

// AgentSettings configures a Presence Agent.
type AgentSettings struct {
	// Hub is the address of the MIRAGE hub. The agent always dials out; the
	// hub never dials in, so the segment the agent sits in is never reachable
	// from the deception zone.
	Hub   string `yaml:"hub" json:"hub"`
	Token string `yaml:"token" json:"token"`
	ID    string `yaml:"id" json:"id"`

	// Addresses are the unused IPs in this segment that the agent claims. They
	// must already exist on the host: the agent binds them, it does not create
	// them (see profiles/README.md).
	Addresses []string         `yaml:"addresses" json:"addresses"`
	Services  []ServiceBinding `yaml:"services" json:"services"`

	// ReconnectMin and ReconnectMax bound the backoff.
	ReconnectMin time.Duration `yaml:"reconnect_min" json:"reconnect_min"`
	ReconnectMax time.Duration `yaml:"reconnect_max" json:"reconnect_max"`
}

func (s *AgentSettings) withDefaults() {
	if s.ReconnectMin <= 0 {
		s.ReconnectMin = time.Second
	}
	if s.ReconnectMax <= 0 {
		s.ReconnectMax = 30 * time.Second
	}
	if len(s.Addresses) == 0 {
		s.Addresses = []string{"0.0.0.0"}
	}
}

// Validate rejects settings that would produce a useless or unsafe agent.
func (s AgentSettings) Validate() error {
	switch {
	case s.Hub == "":
		return errors.New("presence: hub address is required")
	case s.Token == "":
		return errors.New("presence: token is required")
	case s.ID == "":
		return errors.New("presence: agent id is required")
	case len(s.Services) == 0:
		return errors.New("presence: no services declared; the agent would claim nothing")
	}
	for _, b := range s.Services {
		if b.Port < 1 || b.Port > 65535 {
			return fmt.Errorf("presence: service %q has an invalid port %d", b.Service, b.Port)
		}
	}
	for _, a := range s.Addresses {
		if a != "0.0.0.0" && net.ParseIP(a) == nil {
			return fmt.Errorf("presence: %q is not a valid address", a)
		}
	}
	return nil
}

// Agent claims addresses in a segment and tunnels what arrives to the hub.
//
// It forwards bytes and nothing else: it never interprets what a decoy sends,
// never executes anything, and holds no credential beyond its own token. An
// attacker who owns the agent gains a byte pipe to a decoy, which is what they
// already had.
type Agent struct {
	set AgentSettings
	log *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
	tunnel    *tunnel
	permitted map[string]bool
	closed    bool
	connected bool
	wg        sync.WaitGroup
}

// NewAgent builds an agent.
func NewAgent(set AgentSettings, log *slog.Logger) (*Agent, error) {
	set.withDefaults()
	if err := set.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Agent{set: set, log: log, permitted: map[string]bool{}}, nil
}

// Run binds the claimed addresses and keeps a tunnel to the hub until the
// context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.bind(); err != nil {
		a.Close()
		return err
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.maintain(ctx)
	}()
	<-ctx.Done()
	return a.Close()
}

// bind claims every address and port pair.
func (a *Agent) bind() error {
	for _, addr := range a.set.Addresses {
		for _, svc := range a.set.Services {
			hostPort := net.JoinHostPort(addr, fmt.Sprint(svc.Port))
			ln, err := net.Listen("tcp", hostPort)
			if err != nil {
				return fmt.Errorf("presence: claim %s: %w", hostPort, err)
			}
			a.mu.Lock()
			a.listeners = append(a.listeners, ln)
			a.mu.Unlock()

			a.log.Info("presence agent claimed an address",
				"addr", ln.Addr().String(), "service", svc.Service)

			a.wg.Add(1)
			go func(ln net.Listener, service string) {
				defer a.wg.Done()
				a.accept(ln, service)
			}(ln, svc.Service)
		}
	}
	return nil
}

// Addrs reports the claimed endpoints, which is how tests learn ephemeral ports.
func (a *Agent) Addrs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.listeners))
	for _, l := range a.listeners {
		out = append(out, l.Addr().String())
	}
	return out
}

// Connected reports whether the tunnel is up.
func (a *Agent) Connected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

func (a *Agent) accept(ln net.Listener, service string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.forward(conn, service)
		}()
	}
}

// forward carries one inbound connection over the tunnel.
func (a *Agent) forward(conn net.Conn, service string) {
	defer conn.Close()

	a.mu.Lock()
	t := a.tunnel
	permitted := a.permitted[service]
	a.mu.Unlock()

	// Fail closed. With no tunnel there is nothing recording, and a decoy that
	// answers while nothing is watching is worse than a closed port: it invites
	// an attacker to spend time somewhere we learn nothing about.
	if t == nil || !permitted {
		a.log.Debug("presence: dropping connection with no tunnel",
			"service", service, "remote", conn.RemoteAddr().String())
		return
	}

	stream, err := t.open(tunnelAddr{"tcp", conn.LocalAddr().String()},
		tunnelAddr{"tcp", conn.RemoteAddr().String()})
	if err != nil {
		return
	}
	defer stream.Close()

	open, _ := json.Marshal(Open{
		Service: service,
		Source:  conn.RemoteAddr().String(),
		Local:   conn.LocalAddr().String(),
	})
	if err := t.send(Frame{Type: FrameOpen, Stream: stream.id, Payload: open}); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		copyBounded(stream, conn)
		done <- struct{}{}
	}()
	go func() {
		copyBounded(conn, stream)
		done <- struct{}{}
	}()
	<-done
}

// copyBounded moves bytes in fixed-size chunks so a single read cannot exceed
// what a frame carries.
func copyBounded(dst net.Conn, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// maintain keeps the tunnel up, reconnecting with backoff.
func (a *Agent) maintain(ctx context.Context) {
	backoff := a.set.ReconnectMin
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := a.connect(ctx); err != nil {
			a.log.Warn("presence: tunnel to the hub failed", "hub", a.set.Hub, "err", err)
		}
		a.mu.Lock()
		a.connected = false
		a.tunnel = nil
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > a.set.ReconnectMax {
			backoff = a.set.ReconnectMax
		}
	}
}

// connect opens one tunnel and carries it until it fails.
func (a *Agent) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", a.set.Hub)
	if err != nil {
		return err
	}
	defer conn.Close()

	hello, _ := json.Marshal(Hello{
		Version: ProtocolVersion, AgentID: a.set.ID, Token: a.set.Token,
		Addresses: a.set.Addresses, Services: a.serviceNames(),
	})
	conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := WriteFrame(conn, Frame{Type: FrameHello, Payload: hello}); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	frame, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if frame.Type == FrameReject {
		var r Reject
		json.Unmarshal(frame.Payload, &r)
		// A rejection is a configuration problem, not a transient one; say so
		// clearly rather than retrying silently forever.
		return fmt.Errorf("the hub refused this agent: %s", r.Reason)
	}
	if frame.Type != FrameAccept {
		return fmt.Errorf("presence: unexpected frame %d during handshake", frame.Type)
	}
	var accept Accept
	if err := json.Unmarshal(frame.Payload, &accept); err != nil {
		return err
	}

	permitted := map[string]bool{}
	for _, s := range accept.Services {
		permitted[s] = true
	}
	for _, s := range a.serviceNames() {
		if !permitted[s] {
			a.log.Warn("presence: the hub does not permit a claimed service; it will not be carried",
				"service", s)
		}
	}

	t := newTunnel(conn, true)
	a.mu.Lock()
	a.tunnel = t
	a.permitted = permitted
	a.connected = true
	a.mu.Unlock()

	a.log.Info("presence agent connected to the hub",
		"hub", a.set.Hub, "decoy", accept.DecoyID, "persona", accept.Persona,
		"services", accept.Services)

	keepalive := time.Duration(accept.KeepAlive) * time.Second
	if keepalive <= 0 {
		keepalive = 30 * time.Second
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(keepalive)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				t.send(Frame{Type: FramePing})
			}
		}
	}()
	defer close(stop)

	for {
		conn.SetReadDeadline(time.Now().Add(keepalive * 3))
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Close()
			return err
		}
		switch frame.Type {
		case FrameData:
			if s := t.stream(frame.Stream); s != nil {
				s.deliver(frame.Payload)
			}
		case FrameClose:
			if s := t.stream(frame.Stream); s != nil {
				s.closeLocal()
			}
		case FramePing:
			t.send(Frame{Type: FramePong, Stream: frame.Stream})
		case FramePong:
		}
	}
}

func (a *Agent) serviceNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range a.set.Services {
		if !seen[s.Service] {
			seen[s.Service] = true
			out = append(out, s.Service)
		}
	}
	return out
}

// Close releases the claimed addresses and drops the tunnel.
func (a *Agent) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	listeners := a.listeners
	t := a.tunnel
	a.listeners = nil
	a.mu.Unlock()

	for _, l := range listeners {
		l.Close()
	}
	if t != nil {
		t.Close()
	}
	a.wg.Wait()
	return nil
}
