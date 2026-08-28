package presence

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Handler serves a tunnelled connection. honeyd.Server satisfies it.
type Handler interface {
	ServeConn(ctx context.Context, conn net.Conn, service, persona, decoyID string, remote net.Addr) error
}

// AgentConfig is what the hub permits one agent to do.
//
// The hub decides, not the agent: an agent sits in someone else's segment and
// must be assumed compromisable, so what it may forward is declared centrally.
type AgentConfig struct {
	ID       string   `yaml:"id" json:"id"`
	DecoyID  string   `yaml:"decoy_id" json:"decoy_id"`
	Persona  string   `yaml:"persona" json:"persona"`
	Services []string `yaml:"services" json:"services"`
}

// HubConfig configures the hub.
type HubConfig struct {
	Listen string        `yaml:"listen" json:"listen"`
	Token  string        `yaml:"token" json:"token"`
	Agents []AgentConfig `yaml:"agents" json:"agents"`
}

// Hub accepts Presence Agents and hands their traffic to the decoy farm.
type Hub struct {
	cfg     HubConfig
	handler Handler
	log     *slog.Logger

	mu        sync.Mutex
	ln        net.Listener
	connected map[string]*agentSession
	// conns tracks accepted agent sockets so that shutdown can close them.
	// Closing only the listener would leave Close waiting on read deadlines
	// that are deliberately long, and a shutdown that takes two minutes is a
	// shutdown nobody waits for.
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

type agentSession struct {
	cfg       AgentConfig
	addresses []string
	remote    string
	since     time.Time
	streams   int
}

// AgentStatus is what the API reports about a connected agent.
type AgentStatus struct {
	ID        string    `json:"id"`
	DecoyID   string    `json:"decoy_id"`
	Persona   string    `json:"persona"`
	Remote    string    `json:"remote"`
	Addresses []string  `json:"addresses"`
	Services  []string  `json:"services"`
	Since     time.Time `json:"since"`
}

// NewHub builds a hub.
func NewHub(cfg HubConfig, handler Handler, log *slog.Logger) (*Hub, error) {
	if cfg.Listen == "" {
		return nil, errors.New("presence: hub listen address is required")
	}
	if cfg.Token == "" {
		// An unauthenticated hub would let anyone on the network project decoys
		// into it, and read whatever those decoys are told.
		return nil, errors.New("presence: hub token is required")
	}
	if len(cfg.Agents) == 0 {
		return nil, errors.New("presence: no agents are declared; the hub would refuse every connection")
	}
	if handler == nil {
		return nil, errors.New("presence: hub needs a handler")
	}
	if log == nil {
		log = slog.Default()
	}
	seen := map[string]bool{}
	for i, a := range cfg.Agents {
		if a.ID == "" {
			return nil, fmt.Errorf("presence: agent %d has no id", i)
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("presence: duplicate agent id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Persona == "" {
			return nil, fmt.Errorf("presence: agent %q has no persona", a.ID)
		}
		if len(a.Services) == 0 {
			return nil, fmt.Errorf("presence: agent %q may forward nothing", a.ID)
		}
	}
	return &Hub{
		cfg: cfg, handler: handler, log: log,
		connected: map[string]*agentSession{},
		conns:     map[net.Conn]struct{}{},
	}, nil
}

// Start binds the hub listener.
func (h *Hub) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", h.cfg.Listen)
	if err != nil {
		return fmt.Errorf("presence: listen %s: %w", h.cfg.Listen, err)
	}
	h.mu.Lock()
	h.ln = ln
	h.mu.Unlock()

	h.log.Info("presence hub listening", "addr", ln.Addr().String(), "agents", len(h.cfg.Agents))

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				h.mu.Lock()
				closed := h.closed
				h.mu.Unlock()
				if closed || errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				h.serveAgent(ctx, conn)
			}()
		}
	}()
	return nil
}

// Addr reports the bound address, which is how tests learn an ephemeral port.
func (h *Hub) Addr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ln == nil {
		return ""
	}
	return h.ln.Addr().String()
}

// Agents reports the connected agents.
func (h *Hub) Agents() []AgentStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AgentStatus, 0, len(h.connected))
	for _, s := range h.connected {
		out = append(out, AgentStatus{
			ID: s.cfg.ID, DecoyID: s.cfg.DecoyID, Persona: s.cfg.Persona,
			Remote: s.remote, Addresses: s.addresses, Services: s.cfg.Services,
			Since: s.since,
		})
	}
	return out
}

// Close stops the hub.
func (h *Hub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	ln := h.ln
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	h.wg.Wait()
	return nil
}

func (h *Hub) agentConfig(id string) (AgentConfig, bool) {
	for _, a := range h.cfg.Agents {
		if a.ID == id {
			return a, true
		}
	}
	return AgentConfig{}, false
}

// serveAgent authenticates one agent and then carries its streams.
func (h *Hub) serveAgent(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.conns, conn)
		h.mu.Unlock()
	}()

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	frame, err := ReadFrame(conn)
	if err != nil || frame.Type != FrameHello {
		h.log.Warn("presence: connection did not start with a hello", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	var hello Hello
	if err := json.Unmarshal(frame.Payload, &hello); err != nil {
		h.log.Warn("presence: malformed hello", "remote", conn.RemoteAddr(), "err", err)
		return
	}

	reject := func(reason string) {
		body, _ := json.Marshal(Reject{Reason: reason})
		WriteFrame(conn, Frame{Type: FrameReject, Payload: body})
		h.log.Warn("presence: agent rejected",
			"agent", hello.AgentID, "remote", conn.RemoteAddr(), "reason", reason)
	}

	if hello.Version != ProtocolVersion {
		reject(fmt.Sprintf("protocol version %d is not supported", hello.Version))
		return
	}
	// Constant time, because the token is the only thing standing between an
	// attacker on the segment and the ability to project decoys of their own.
	if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(h.cfg.Token)) != 1 {
		reject("authentication failed")
		return
	}
	cfg, known := h.agentConfig(hello.AgentID)
	if !known {
		reject("unknown agent id")
		return
	}

	// The agent asks; the hub decides. Anything it requested that is not
	// declared here is silently not carried.
	permitted := map[string]bool{}
	for _, s := range cfg.Services {
		permitted[s] = true
	}
	body, _ := json.Marshal(Accept{
		Services: cfg.Services, DecoyID: cfg.DecoyID, Persona: cfg.Persona, KeepAlive: 30,
	})
	if err := WriteFrame(conn, Frame{Type: FrameAccept, Payload: body}); err != nil {
		return
	}

	addresses := hello.Addresses
	if len(addresses) > 4096 {
		addresses = addresses[:4096]
	}
	session := &agentSession{
		cfg: cfg, addresses: addresses, remote: conn.RemoteAddr().String(), since: time.Now(),
	}
	h.mu.Lock()
	h.connected[cfg.ID] = session
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.connected, cfg.ID)
		h.mu.Unlock()
		h.log.Info("presence agent disconnected", "agent", cfg.ID)
	}()

	h.log.Info("presence agent connected",
		"agent", cfg.ID, "remote", conn.RemoteAddr().String(),
		"addresses", len(addresses), "services", cfg.Services)

	t := newTunnel(conn, false)
	defer t.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Generous: an idle agent still pings, and a decoy session can be long.
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		frame, err := ReadFrame(conn)
		if err != nil {
			return
		}

		switch frame.Type {
		case FrameOpen:
			var open Open
			if err := json.Unmarshal(frame.Payload, &open); err != nil {
				continue
			}
			if !permitted[open.Service] {
				h.log.Warn("presence: agent tried to forward an undeclared service",
					"agent", cfg.ID, "service", open.Service)
				t.send(Frame{Type: FrameClose, Stream: frame.Stream})
				continue
			}
			stream, err := t.accept(frame.Stream, parseAddr(open.Local), parseAddr(open.Source))
			if err != nil {
				t.send(Frame{Type: FrameClose, Stream: frame.Stream})
				continue
			}
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				defer stream.Close()
				// The decoy sees the attacker's real address, not the agent's.
				err := h.handler.ServeConn(ctx, stream, open.Service, cfg.Persona, cfg.DecoyID,
					parseAddr(open.Source))
				if err != nil {
					h.log.Debug("presence: tunnelled session ended",
						"agent", cfg.ID, "service", open.Service, "err", err)
				}
			}()

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
			// nothing to do

		default:
			h.log.Warn("presence: unknown frame type", "agent", cfg.ID, "type", frame.Type)
		}
	}
}
