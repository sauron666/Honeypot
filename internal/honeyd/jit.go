package honeyd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// JIT spawns a decoy in response to scanning: an attacker probes a subnet for
// MSSQL, and within seconds an MSSQL decoy appears on a neighbouring address.
// The attacker finds exactly what they were hunting for, which is the point —
// the ratio of "interesting finds" to "decoys" approaches 100%.
//
// It works by listening on a set of addresses for connection attempts to ports
// with no declared service. When a SYN arrives for a port that matches a
// registered protocol (SSH on 22, SMB on 445, MSSQL on 1433...), JIT binds
// that service on that address, and the next attempt gets a real answer.
//
// The spawned listener is temporary: it shuts down after an idle period, so
// addressing stays clean between scans. And it is jittered: a decoy that
// appears exactly one RTT after a probe is a decoy that announces itself
// as reactive. A short random delay (100-800ms) masks the mechanism.
//
// JIT only creates listeners on addresses the farm already binds, so it never
// reaches into a subnet it was not invited to. The compute driver is not
// involved — these are emulated services, not VMs.

// JITConfig configures the reactive spawner.
//
// NOTE: as of now the spawner is staged, not wired into the server — nothing
// calls OnProbe in production. It is kept because the reactive idea is sound and
// the anti-scanner guard below makes it safe to enable later. When it is wired,
// the guard is what stops a port sweep (nmap) from making a decoy appear on
// every well-known port at once.
type JITConfig struct {
	// Addresses to watch for probes. Empty means the farm's own bind addresses.
	Addresses []string `yaml:"addresses" json:"addresses"`
	// IdleTimeout is how long a JIT listener stays up after the last session.
	IdleTimeout time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	// Enabled turns the feature on. It is off by default because a feature that
	// appears to create infrastructure should not surprise an operator who did
	// not ask for it.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// --- scanner resistance (so an nmap sweep does not spawn everything) ---

	// ScanThreshold is how many DISTINCT ports one source may probe within
	// ScanWindow before it is treated as a scanner and suppressed. A port sweep
	// hits dozens instantly; a targeted attacker hits one or two. Default 4.
	ScanThreshold int `yaml:"scan_threshold" json:"scan_threshold"`
	// ScanWindow is the sliding window for ScanThreshold. Default 10s.
	ScanWindow time.Duration `yaml:"scan_window" json:"scan_window"`
	// ScannerCooldown is how long a flagged scanner stays suppressed. Default 5m.
	ScannerCooldown time.Duration `yaml:"scanner_cooldown" json:"scanner_cooldown"`
	// MaxActive caps how many reactive decoys can be up at once, a hard backstop
	// against resource exhaustion even if the heuristics are fooled. Default 16.
	MaxActive int `yaml:"max_active" json:"max_active"`
}

// wellKnownPort maps a port to the service most commonly found on it.
var wellKnownPort = map[int]string{
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	80:    "http",
	110:   "generic",
	135:   "generic",
	139:   "smb",
	443:   "http",
	445:   "smb",
	1433:  "mssql",
	1521:  "generic",
	3306:  "mysql",
	3389:  "generic",
	5432:  "generic",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http",
	8443:  "http",
	27017: "generic",
}

// JITSpawner watches for probes and creates temporary decoys.
type JITSpawner struct {
	farm      *Server
	log       *slog.Logger
	persona   string
	decoyID   string
	timeout   time.Duration
	maxActive int
	guard     *scanGuard
	emit      func(context.Context, *event.Event)

	mu      sync.Mutex
	spawned map[string]context.CancelFunc // key: "addr:port"
}

// NewJITSpawner builds a spawner that creates services on the given farm.
func NewJITSpawner(farm *Server, persona, decoyID string, cfg JITConfig,
	emit func(context.Context, *event.Event), log *slog.Logger) *JITSpawner {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 15 * time.Minute
	}
	if cfg.MaxActive <= 0 {
		cfg.MaxActive = 16
	}
	if log == nil {
		log = slog.Default()
	}
	return &JITSpawner{
		farm: farm, log: log, persona: persona, decoyID: decoyID,
		timeout: cfg.IdleTimeout, maxActive: cfg.MaxActive,
		guard: newScanGuard(cfg.ScanThreshold, cfg.ScanWindow, cfg.ScannerCooldown),
		emit:  emit, spawned: map[string]context.CancelFunc{},
	}
}

// OnProbe is called when a connection attempt from sourceIP arrives at a port
// with no declared service. If the port maps to a known protocol AND the source
// is not behaving like a scanner, it spawns a temporary listener.
//
// The scanner guard is the whole point of the sourceIP argument: a port sweep
// (nmap) touches many distinct ports from one source in a moment, and must NOT
// make a decoy appear on each — that both exhausts resources and screams
// "reactive honeypot". The guard suppresses such a source; a targeted attacker,
// who focuses on one or two ports, still gets its decoy.
func (j *JITSpawner) OnProbe(ctx context.Context, sourceIP, addr string, port int) {
	svc, ok := wellKnownPort[port]
	if !ok {
		return
	}
	if _, exists := serviceRegistry[svc]; !exists {
		return
	}

	// Scanner resistance: record the probe and bail if this source is sweeping.
	if !j.guard.allow(sourceIP, port) {
		j.log.Debug("JIT: suppressed reactive spawn for a scanning source",
			"source", sourceIP, "port", port)
		return
	}

	key := fmt.Sprintf("%s:%d", addr, port)
	j.mu.Lock()
	if _, already := j.spawned[key]; already {
		j.mu.Unlock()
		return
	}
	// Hard backstop: never exceed the active cap, whatever the heuristics say.
	if len(j.spawned) >= j.maxActive {
		j.mu.Unlock()
		j.log.Debug("JIT: at max active reactive decoys; not spawning", "max", j.maxActive)
		return
	}
	spawnCtx, cancel := context.WithCancel(ctx)
	j.spawned[key] = cancel
	j.mu.Unlock()

	// Jitter: a decoy that appears instantly after a probe is a tell.
	jitter := time.Duration(50+hashPort(addr, port)%750) * time.Millisecond
	time.Sleep(jitter)

	j.log.Info("JIT: spawning reactive decoy",
		"addr", addr, "port", port, "service", svc, "persona", j.persona)

	e := event.New(event.ClassDecoyInteraction, 1, event.SeverityMedium, event.PlaneDirector).
		WithMessage("JIT: reactive %s decoy spawned at %s:%d in response to scanning", svc, addr, port)
	e.Mirage.DecoyID = j.decoyID
	e.Mirage.Service = svc
	j.emit(ctx, e)

	go j.runTemporary(spawnCtx, key, addr, port, svc)
}

// runTemporary binds a service and removes it after the idle timeout.
func (j *JITSpawner) runTemporary(ctx context.Context, key, addr string, port int, svc string) {
	defer func() {
		j.mu.Lock()
		delete(j.spawned, key)
		j.mu.Unlock()
		j.log.Info("JIT: temporary decoy expired", "addr", addr, "port", port, "service", svc)
	}()

	hostPort := net.JoinHostPort(addr, fmt.Sprint(port))
	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		j.log.Debug("JIT: could not bind", "addr", hostPort, "err", err)
		return
	}
	defer ln.Close()

	p, err := BuildPersona(j.persona, j.farm.cfg.DeploySeed)
	if err != nil {
		return
	}
	factory, ok := serviceRegistry[svc]
	if !ok {
		return
	}
	service, err := factory(p, nil)
	if err != nil {
		return
	}

	idle := time.NewTimer(j.timeout)
	defer idle.Stop()

	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-idle.C:
			ln.Close()
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		idle.Reset(j.timeout)
		go func() {
			defer conn.Close()
			sess := j.farm.newSession(ctx, svc, p, j.decoyID, conn.RemoteAddr(), conn.LocalAddr())
			service.Serve(ctx, conn, sess)
			j.farm.finishSession(sess, nil)
		}()
	}
}

// Active reports how many JIT listeners are currently up.
func (j *JITSpawner) Active() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.spawned)
}

// Close stops all temporary listeners.
func (j *JITSpawner) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, cancel := range j.spawned {
		cancel()
	}
	j.spawned = map[string]context.CancelFunc{}
}

func hashPort(addr string, port int) int {
	h := 0
	for _, c := range addr {
		h = h*31 + int(c)
	}
	return (h ^ (port * 7919)) & 0x7fffffff
}

// scanGuard tells a port scanner apart from a targeted attacker so that a sweep
// does not trigger a reactive decoy on every port. It counts the DISTINCT ports
// a single source probes inside a sliding window; past a threshold the source
// is flagged as a scanner and suppressed for a cooldown. It is deliberately
// per-source and memory-bounded (old probes are pruned on access).
type scanGuard struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	seen    map[string]map[int]time.Time // source -> port -> last probe
	flagged map[string]time.Time         // source -> suppression expiry
}

func newScanGuard(threshold int, window, cooldown time.Duration) *scanGuard {
	if threshold <= 0 {
		threshold = 4
	}
	if window <= 0 {
		window = 10 * time.Second
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	return &scanGuard{
		window: window, threshold: threshold, cooldown: cooldown, now: time.Now,
		seen: map[string]map[int]time.Time{}, flagged: map[string]time.Time{},
	}
}

// allow records a probe from source to port and reports whether a reactive
// decoy may be spawned. A source in scanner-cooldown, or one that crosses the
// distinct-port threshold with this probe, is denied.
func (g *scanGuard) allow(source string, port int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	// Still serving a cooldown for a previously flagged scanner?
	if exp, ok := g.flagged[source]; ok {
		if now.Before(exp) {
			g.record(source, port, now)
			return false
		}
		delete(g.flagged, source)
	}

	g.record(source, port, now)
	if g.distinct(source, now) >= g.threshold {
		// This source is sweeping: flag it and suppress for the cooldown.
		g.flagged[source] = now.Add(g.cooldown)
		return false
	}
	return true
}

// record notes a probe and prunes entries older than the window.
func (g *scanGuard) record(source string, port int, now time.Time) {
	ports := g.seen[source]
	if ports == nil {
		ports = map[int]time.Time{}
		g.seen[source] = ports
	}
	ports[port] = now
	cutoff := now.Add(-g.window)
	for p, t := range ports {
		if t.Before(cutoff) {
			delete(ports, p)
		}
	}
	if len(ports) == 0 {
		delete(g.seen, source)
	}
}

// distinct counts how many different ports source has probed within the window.
func (g *scanGuard) distinct(source string, now time.Time) int {
	cutoff := now.Add(-g.window)
	n := 0
	for _, t := range g.seen[source] {
		if !t.Before(cutoff) {
			n++
		}
	}
	return n
}
