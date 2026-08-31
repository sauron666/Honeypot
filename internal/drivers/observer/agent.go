package observer

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// AgentInfo describes the agent (in-guest sensor) observer.
//
// This is the honest counterpart to DRAKVUF: where agentless VMI needs Xen (or
// a KVMi-patched host), the agent observer works on ANY hypervisor because the
// visibility comes from inside the guest — standard enterprise telemetry
// (Linux auditd/eBPF, Windows Sysmon) or a PTY-recording shell, forwarded to
// the director. It deliberately does NOT claim CapAgentless: there is something
// inside the guest, and the console must say so plainly.
func AgentInfo() drivers.Info {
	return drivers.Info{
		Name: "agent",
		Kind: drivers.KindObserver,
		Summary: "In-guest sensor: full-OS decoys stream process/file/command " +
			"telemetry (auditd/eBPF on Linux, Sysmon on Windows) to the director " +
			"over an authenticated channel. Works on every hypervisor (KVM, " +
			"Proxmox, VMware, Hyper-V) — unlike agentless VMI. Agent-based: there " +
			"is a sensor inside the guest, declared honestly (not CapAgentless).",
		Capabilities: []drivers.Capability{
			drivers.CapTraceProcess, drivers.CapTraceFile, drivers.CapTraceRegistry,
		},
	}
}

// Agent is the director-side receiver for in-guest sensors. Guest collectors
// POST normalised sightings to it; it fans each one out to the Observe stream
// for the decoy it names, so agent telemetry joins the evidence chain and the
// engagement tracker exactly like a DRAKVUF sighting.
type Agent struct {
	token  string
	srv    *http.Server
	ln     net.Listener
	listen string

	mu   sync.Mutex
	subs map[string]chan drivers.Sighting // decoyID -> subscriber
	seen map[string]time.Time             // decoyID -> last event, for status
	done bool
}

// NewAgent builds the agent observer. Config keys:
//
//	"listen"    — address guest sensors connect to (default 127.0.0.1:8423)
//	"token"     — shared bearer token the sensors must present (required)
//	"tls_cert"  — optional PEM cert to serve TLS (recommended off-localhost)
//	"tls_key"   — optional PEM key for tls_cert
//
// The token is required: an unauthenticated ingest endpoint on a security
// product is a liability, and off-localhost the link should carry TLS (or run
// inside the presence overlay tunnel). This is stated in the tutorial.
func NewAgent(cfg map[string]any) (drivers.Driver, error) {
	get := func(k, def string) string {
		if v, ok := cfg[k].(string); ok && v != "" {
			return v
		}
		return def
	}
	listen := get("listen", "127.0.0.1:8423")
	token := get("token", "")
	if token == "" {
		return nil, fmt.Errorf("observer/agent: \"token\" is required — the shared secret " +
			"guest sensors present; an open ingest endpoint would let anyone inject telemetry")
	}

	a := &Agent{
		token:  token,
		listen: listen,
		subs:   map[string]chan drivers.Sighting{},
		seen:   map[string]time.Time{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", a.handleIngest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("observer/agent: cannot listen on %s: %w", listen, err)
	}
	a.ln = ln
	a.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cert := get("tls_cert", ""); cert != "" {
		key := get("tls_key", "")
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("observer/agent: load TLS keypair: %w", err)
		}
		a.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		go a.srv.ServeTLS(ln, "", "")
	} else {
		go a.srv.Serve(ln)
	}
	return a, nil
}

func (a *Agent) Info() drivers.Info          { return AgentInfo() }
func (a *Agent) Probe(context.Context) error { return nil }

func (a *Agent) Close() error {
	a.mu.Lock()
	a.done = true
	for id, ch := range a.subs {
		close(ch)
		delete(a.subs, id)
	}
	a.mu.Unlock()
	if a.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return a.srv.Shutdown(ctx)
	}
	return nil
}

// Attach and Detach are no-ops: the guest sensor connects on its own once the
// decoy is up. Observe is what wires the stream.
func (a *Agent) Attach(context.Context, string) error { return nil }
func (a *Agent) Detach(context.Context, string) error { return nil }

// DumpMemory is not available from an in-guest agent (that is a hypervisor-level
// capability). Declared honestly via the missing CapMemoryDump.
func (a *Agent) DumpMemory(context.Context, string, string) error {
	return drivers.ErrObserveUnsupported
}

// Observe returns the stream of sightings the guest sensor forwards for this
// decoy. The channel is buffered so a burst of guest events never blocks the
// HTTP receiver; on overflow events are dropped (the head-of-line lesson from
// the presence multiplexer), never blocked.
func (a *Agent) Observe(ctx context.Context, decoyID string) (<-chan drivers.Sighting, error) {
	a.mu.Lock()
	if a.done {
		a.mu.Unlock()
		return nil, fmt.Errorf("observer/agent: closed")
	}
	ch := make(chan drivers.Sighting, 256)
	// Replace any previous subscriber for this decoy.
	if old, ok := a.subs[decoyID]; ok {
		close(old)
	}
	a.subs[decoyID] = ch
	a.mu.Unlock()

	// Close the channel when the caller's context ends, so the app's Observe
	// goroutine exits cleanly on stopObserving.
	go func() {
		<-ctx.Done()
		a.mu.Lock()
		if cur, ok := a.subs[decoyID]; ok && cur == ch {
			close(ch)
			delete(a.subs, decoyID)
		}
		a.mu.Unlock()
	}()
	return ch, nil
}

// handleIngest accepts sightings from a guest sensor. The body is either a
// single JSON sighting, a JSON array, or newline-delimited JSON — whichever the
// collector finds easiest to emit.
func (a *Agent) handleIngest(w http.ResponseWriter, r *http.Request) {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.Header.Get("X-Mirage-Token")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	sightings, err := parseSightings(body)
	if err != nil {
		http.Error(w, "parse error: "+err.Error(), http.StatusBadRequest)
		return
	}
	accepted := 0
	for _, s := range sightings {
		if s.DecoyID == "" {
			continue
		}
		if s.Time.IsZero() {
			s.Time = time.Now()
		}
		if a.deliver(s) {
			accepted++
		}
	}
	writeAgentJSON(w, map[string]any{"accepted": accepted, "received": len(sightings)})
}

// deliver fans one sighting to its decoy's subscriber without blocking.
func (a *Agent) deliver(s drivers.Sighting) bool {
	a.mu.Lock()
	a.seen[s.DecoyID] = s.Time
	ch, ok := a.subs[s.DecoyID]
	a.mu.Unlock()
	if !ok {
		return false // no active Observe for this decoy; the event is dropped
	}
	select {
	case ch <- s:
		return true
	default:
		// Buffer full: drop rather than block the receiver. A flooding sensor
		// must never stall the director.
		return false
	}
}

// parseSightings accepts a single object, an array, or newline-delimited JSON.
func parseSightings(body []byte) ([]drivers.Sighting, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []drivers.Sighting
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	if trimmed[0] == '{' && !strings.ContainsRune(trimmed, '\n') {
		var one drivers.Sighting
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil, err
		}
		return []drivers.Sighting{one}, nil
	}
	// Newline-delimited JSON.
	var out []drivers.Sighting
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s drivers.Sighting
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Addr returns the address the receiver is listening on (for status/tests).
func (a *Agent) Addr() string {
	if a.ln != nil {
		return a.ln.Addr().String()
	}
	return a.listen
}

func writeAgentJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

var _ drivers.ObserverDriver = (*Agent)(nil)
