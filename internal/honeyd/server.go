package honeyd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/version"
)

// Service is one emulated protocol.
type Service interface {
	// Type is the service name used in configuration and events ("ssh").
	Type() string
	// Serve handles one connection. Returning an error is normal -- attackers
	// disconnect rudely -- and is logged at debug level, not surfaced.
	Serve(ctx context.Context, conn net.Conn, s *Session) error
}

// PacketService is a service that speaks UDP. It is answered one datagram at a
// time and must be stateless.
//
// Containment rule for UDP (docs/04): a decoy must never become a reflection
// and amplification weapon aimed at a third party. UDP source addresses are
// trivially spoofed, so the server -- not each service -- enforces three limits:
//
//   - a reply may exceed the request by at most udpReplyHeadroom bytes,
//   - a reply may never exceed udpReplyCap bytes,
//   - each source address gets udpPerSecond datagrams, bursting to udpBurst.
//
// Together these hold the amplification factor near one and cap what a spoofed
// victim can receive at a few kilobytes per second, which is far below the six-
// to hundred-fold gain that makes a reflector worth using. Strict equality
// would be safer still, but it would silence protocols like SNMP whose answers
// are inherently a few bytes longer than their questions -- a decoy that never
// answers is a decoy an attacker skips.
type PacketService interface {
	Service
	ServePacket(ctx context.Context, s *Session, payload []byte) ([]byte, error)
}

// ServiceFactory builds a service for a persona.
type ServiceFactory func(p *Persona, opts map[string]any) (Service, error)

var serviceRegistry = map[string]ServiceFactory{}

// RegisterService adds a protocol implementation to the catalogue.
func RegisterService(name string, f ServiceFactory) { serviceRegistry[name] = f }

// ServiceNames lists the registered protocols.
func ServiceNames() []string {
	out := make([]string, 0, len(serviceRegistry))
	for n := range serviceRegistry {
		out = append(out, n)
	}
	return out
}

// BoundListener describes a listening decoy endpoint.
type BoundListener struct {
	Service string `json:"service"`
	Address string `json:"address"`
	Proto   string `json:"proto"`
	DecoyID string `json:"decoy_id"`
	Persona string `json:"persona"`
}

// EngagementResolver assigns an engagement id to an interaction, so that every
// event from one attacker across many decoys and services stitches into one
// story. The honeyd package only needs the id.
type EngagementResolver interface {
	Resolve(srcIP, decoyID, service string) string
}

// ListenerConfig is one bound port on one address.
//
// Address is what makes projection possible: a single process can present the
// same decoy, or different decoys, on every unused address in a subnet. Leave
// it empty to use the farm's default bind address.
type ListenerConfig struct {
	Service string         `yaml:"service" json:"service"`
	Address string         `yaml:"address" json:"address"`
	Port    int            `yaml:"port" json:"port"`
	Persona string         `yaml:"persona" json:"persona"`
	DecoyID string         `yaml:"decoy_id" json:"decoy_id"`
	Options map[string]any `yaml:"options" json:"options"`
}

// Config configures the service farm.
type Config struct {
	Identity   Identity
	DeploySeed string
	BindAddr   string
	Listeners  []ListenerConfig

	MaxSessionDuration time.Duration
	IdleTimeout        time.Duration
	MaxTranscriptBytes int
	// MaxConnsPerIP bounds concurrent sessions from one source. A honeypot is
	// an inviting target for a resource-exhaustion attack precisely because it
	// accepts everything.
	MaxConnsPerIP int
	MaxConnsTotal int
}

// withDefaults fills in the values an operator should not have to think about.
func (c Config) withDefaults() Config {
	if c.BindAddr == "" {
		c.BindAddr = "0.0.0.0"
	}
	if c.MaxSessionDuration == 0 {
		c.MaxSessionDuration = 30 * time.Minute
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.MaxTranscriptBytes == 0 {
		c.MaxTranscriptBytes = 256 * 1024
	}
	if c.MaxConnsPerIP == 0 {
		c.MaxConnsPerIP = 25
	}
	if c.MaxConnsTotal == 0 {
		c.MaxConnsTotal = 2000
	}
	if c.DeploySeed == "" {
		// A random seed per process is wrong for a real deployment (artifacts
		// would change on restart) but is the safe default: it guarantees no
		// two installs are byte-identical, which is what defeats signatures.
		c.DeploySeed = event.NewID()
	}
	return c
}

// Server runs the emulated service farm.
type Server struct {
	cfg      Config
	log      *slog.Logger
	emitter  Emitter
	resolver EngagementResolver

	personas map[string]*Persona

	mu          sync.Mutex
	bound       []BoundListener
	listeners   []net.Listener
	packetConns []net.PacketConn
	perIP       map[string]int
	total       int
	sessions    map[string]*Session
	udpBudget   map[string]*rateBucket

	wg     sync.WaitGroup
	closed bool
}

// NewServer builds the farm. Personas and services are instantiated up front so
// that a configuration error fails at startup rather than at first contact.
func NewServer(cfg Config, emitter Emitter, resolver EngagementResolver, log *slog.Logger) (*Server, error) {
	cfg = cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	if emitter == nil {
		return nil, errors.New("honeyd: emitter is required")
	}
	if len(cfg.Listeners) == 0 {
		return nil, errors.New("honeyd: no listeners configured")
	}

	s := &Server{
		cfg: cfg, log: log, emitter: emitter, resolver: resolver,
		personas:  map[string]*Persona{},
		perIP:     map[string]int{},
		sessions:  map[string]*Session{},
		udpBudget: map[string]*rateBucket{},
	}
	for i, l := range cfg.Listeners {
		if l.Persona == "" {
			return nil, fmt.Errorf("honeyd: listener %d (%s/%d) has no persona", i, l.Service, l.Port)
		}
		if _, ok := serviceRegistry[l.Service]; !ok {
			return nil, fmt.Errorf("honeyd: listener %d: unknown service %q (have: %v)", i, l.Service, ServiceNames())
		}
		if _, err := s.persona(l.Persona); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// persona instantiates a persona once and caches it, so every service on a
// decoy shares one consistent identity.
func (s *Server) persona(name string) (*Persona, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.personas[name]; ok {
		return p, nil
	}
	p, err := BuildPersona(name, s.cfg.DeploySeed)
	if err != nil {
		return nil, err
	}
	s.personas[name] = p
	return p, nil
}

// Start binds every listener. It returns on the first bind failure with all
// previously bound listeners closed, so a partial farm never runs unnoticed.
func (s *Server) Start(ctx context.Context) error {
	for _, lc := range s.cfg.Listeners {
		if err := s.startListener(ctx, lc); err != nil {
			s.Close()
			return err
		}
	}
	return nil
}

func (s *Server) startListener(ctx context.Context, lc ListenerConfig) error {
	p, err := s.persona(lc.Persona)
	if err != nil {
		return err
	}
	svc, err := serviceRegistry[lc.Service](p, lc.Options)
	if err != nil {
		return fmt.Errorf("honeyd: build %s service: %w", lc.Service, err)
	}

	decoyID := lc.DecoyID
	if decoyID == "" {
		decoyID = s.cfg.Identity.DecoyID
	}
	bindHost := lc.Address
	if bindHost == "" {
		bindHost = s.cfg.BindAddr
	}
	addr := net.JoinHostPort(bindHost, fmt.Sprint(lc.Port))

	if ps, ok := svc.(PacketService); ok {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("honeyd: listen udp %s for %s: %w", addr, lc.Service, err)
		}
		s.mu.Lock()
		s.packetConns = append(s.packetConns, pc)
		s.bound = append(s.bound, BoundListener{
			Service: lc.Service, Address: pc.LocalAddr().String(), Proto: "udp",
			DecoyID: decoyID, Persona: lc.Persona,
		})
		s.mu.Unlock()

		s.log.Info("decoy listening", "service", lc.Service, "addr", addr, "proto", "udp",
			"persona", lc.Persona, "hostname", p.Hostname, "decoy_id", decoyID)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.packetLoop(ctx, pc, ps, p, decoyID)
		}()
		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("honeyd: listen %s for %s: %w", addr, lc.Service, err)
	}

	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.bound = append(s.bound, BoundListener{
		Service: lc.Service, Address: ln.Addr().String(), Proto: "tcp",
		DecoyID: decoyID, Persona: lc.Persona,
	})
	s.mu.Unlock()

	s.log.Info("decoy listening",
		"service", lc.Service, "addr", addr, "proto", "tcp", "persona", lc.Persona,
		"hostname", p.Hostname, "decoy_id", decoyID)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln, svc, p, decoyID)
	}()
	return nil
}

// packetLoop serves a UDP service, enforcing the anti-amplification rules.
func (s *Server) packetLoop(ctx context.Context, pc net.PacketConn, svc PacketService, p *Persona, decoyID string) {
	buf := make([]byte, 64*1024)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
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
		payload := append([]byte(nil), buf[:n]...)

		ip := hostOf(remote)
		if !s.udpAllowed(ip) {
			continue // rate limited: record nothing, answer nothing
		}

		sess := s.newSession(ctx, svc.Type(), p, decoyID, remote, pc.LocalAddr())
		sess.Record("in", payload)

		reply, err := svc.ServePacket(ctx, sess, payload)
		if err != nil {
			s.log.Debug("udp service error", "service", svc.Type(), "src", ip, "err", err)
		}
		if len(reply) > 0 {
			if amplificationSafe(len(payload), len(reply)) {
				sess.Record("out", reply)
				pc.WriteTo(reply, remote)
			} else {
				e := sess.Event(event.ClassContainment, 2, event.SeverityLow).
					WithMessage("udp reply withheld: %d bytes would amplify a %d byte request",
						len(reply), len(payload))
				e.Set("request_bytes", len(payload)).Set("reply_bytes", len(reply)).
					Set("limit_headroom", udpReplyHeadroom).Set("limit_cap", udpReplyCap)
				sess.Emit(e)
			}
		}
		s.finishSession(sess, nil)
	}
}

// udpAllowed applies a per-source token bucket. UDP sources are trivially
// spoofed, so the limit is deliberately tight.
func (s *Server) udpAllowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.udpBudget[ip]
	if !ok {
		if len(s.udpBudget) > 20000 {
			s.udpBudget = map[string]*rateBucket{}
		}
		b = &rateBucket{tokens: udpBurst, last: time.Now()}
		s.udpBudget[ip] = b
	}
	return b.take()
}

// rateBucket is a simple token bucket.
type rateBucket struct {
	tokens float64
	last   time.Time
}

const (
	udpBurst     = 20.0 // datagrams a new source may send immediately
	udpPerSecond = 5.0  // sustained rate per source

	// udpReplyHeadroom and udpReplyCap bound how much larger than its request a
	// reply may be. See the PacketService comment for the reasoning.
	udpReplyHeadroom = 64
	udpReplyCap      = 512
)

// amplificationSafe reports whether a reply of replyLen bytes may be sent in
// answer to a request of reqLen bytes.
func amplificationSafe(reqLen, replyLen int) bool {
	return replyLen <= reqLen+udpReplyHeadroom && replyLen <= udpReplyCap
}

func (b *rateBucket) take() bool {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * udpPerSecond
	if b.tokens > udpBurst {
		b.tokens = udpBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, svc Service, p *Persona, decoyID string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept failed", "service", svc.Type(), "err", err)
			// Back off briefly so a persistent accept error does not spin.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn, svc, p, decoyID)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, svc Service, p *Persona, decoyID string) {
	defer conn.Close()

	ip := hostOf(conn.RemoteAddr())
	if !s.admit(ip) {
		// Shedding load is itself worth recording: it is how we learn a decoy
		// is being used as a DoS amplifier or scanned aggressively.
		e := event.New(event.ClassContainment, 1, event.SeverityMedium, event.PlaneHoneyd)
		e.Metadata.Product = event.Product{Name: version.Product, VendorName: version.Vendor, Version: version.Version, Feature: "honeyd"}
		e.Mirage.TenantID, e.Mirage.SiteID, e.Mirage.DecoyID = s.cfg.Identity.TenantID, s.cfg.Identity.SiteID, decoyID
		e.Mirage.Service = svc.Type()
		e.WithSrc(ip, 0).WithMessage("connection refused: per-source limit reached")
		e.Set("limit", s.cfg.MaxConnsPerIP)
		s.emitter.Emit(ctx, e)
		return
	}
	defer s.release(ip)

	sctx, cancel := context.WithTimeout(ctx, s.cfg.MaxSessionDuration)
	defer cancel()

	sess := s.newSession(sctx, svc.Type(), p, decoyID, conn.RemoteAddr(), conn.LocalAddr())
	sess.Emit(sess.Event(event.ClassNetworkActivity, 1, event.SeverityLow).
		WithMessage("connection to %s decoy %s", svc.Type(), p.Hostname))

	conn.SetDeadline(sess.deadline)
	err := svc.Serve(sctx, conn, sess)
	s.finishSession(sess, err)

	if err != nil {
		s.log.Debug("session ended", "service", svc.Type(), "src", sess.SrcIP(), "err", err)
	}
}

// newSession registers an interaction and assigns it to an engagement.
func (s *Server) newSession(ctx context.Context, service string, p *Persona, decoyID string,
	remote, local net.Addr) *Session {

	sess := &Session{
		ID:      event.ShortID("ses"),
		Service: service,
		Identity: Identity{
			TenantID: s.cfg.Identity.TenantID, SiteID: s.cfg.Identity.SiteID,
			DecoyID: decoyID, Persona: p.Name,
		},
		Remote:    remote,
		Local:     local,
		Started:   time.Now(),
		Persona:   p,
		emitter:   s.emitter,
		ctx:       ctx,
		deadline:  time.Now().Add(s.cfg.MaxSessionDuration),
		maxScript: s.cfg.MaxTranscriptBytes,
	}
	if s.resolver != nil {
		sess.EngagementID = s.resolver.Resolve(sess.SrcIP(), decoyID, service)
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// finishSession emits the closing record that carries the transcript.
func (s *Server) finishSession(sess *Session, err error) {
	s.mu.Lock()
	delete(s.sessions, sess.ID)
	s.mu.Unlock()

	transcript, truncated := sess.Transcript()
	end := sess.Event(event.ClassNetworkActivity, 2, event.SeverityLow).
		WithMessage("session closed after %s (%d events)",
			time.Since(sess.Started).Round(time.Millisecond), sess.EventCount())
	end.Set("duration_ms", time.Since(sess.Started).Milliseconds()).
		Set("transcript", transcript).
		Set("transcript_truncated", truncated).
		Set("credentials_offered", len(sess.Credentials()))
	if err != nil {
		end.Set("close_reason", err.Error())
	}
	sess.Emit(end)
}

// admit applies the concurrency limits.
func (s *Server) admit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.total >= s.cfg.MaxConnsTotal || s.perIP[ip] >= s.cfg.MaxConnsPerIP {
		return false
	}
	s.perIP[ip]++
	s.total++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.perIP[ip] <= 1 {
		delete(s.perIP, ip)
	} else {
		s.perIP[ip]--
	}
}

// ActiveSessions reports the number of live interactions.
func (s *Server) ActiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Addrs reports the bound addresses, which is how tests learn the port when
// they bind to :0.
func (s *Server) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.listeners)+len(s.packetConns))
	for _, l := range s.listeners {
		out = append(out, l.Addr().String())
	}
	for _, pc := range s.packetConns {
		out = append(out, pc.LocalAddr().String())
	}
	return out
}

// Bound returns the listening endpoints, which is how the assurance runner and
// the API learn what is actually deployed.
func (s *Server) Bound() []BoundListener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]BoundListener(nil), s.bound...)
}

// Personas returns the instantiated personas, keyed by name.
func (s *Server) Personas() map[string]*Persona {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*Persona, len(s.personas))
	for k, v := range s.personas {
		out[k] = v
	}
	return out
}

// Close stops listening and waits for in-flight sessions to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listeners := s.listeners
	packets := s.packetConns
	s.listeners, s.packetConns = nil, nil
	s.mu.Unlock()

	for _, l := range listeners {
		l.Close()
	}
	for _, pc := range packets {
		pc.Close()
	}
	s.wg.Wait()
	return nil
}

func hostOf(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
