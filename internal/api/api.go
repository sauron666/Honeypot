// Package api serves the management API and the operator UI.
//
// It is deliberately read-mostly: the control plane exposes evidence and state,
// and nothing here can reach into the decoy segment. The API is expected to be
// bound to a management interface (docs/04); it warns loudly when it is not.
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/assure"
	"github.com/sauron666/Honeypot/internal/compliance"
	"github.com/sauron666/Honeypot/internal/config"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/farm"
	"github.com/sauron666/Honeypot/internal/forge"
	"github.com/sauron666/Honeypot/internal/graph"
	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/presence"
	"github.com/sauron666/Honeypot/internal/store"
	"github.com/sauron666/Honeypot/internal/tokens"
	"github.com/sauron666/Honeypot/internal/version"
)

//go:embed web
var webFS embed.FS

// Deps are the things the API reads from.
type Deps struct {
	Store      store.EventStore
	Tracker    *engagement.Tracker
	Farm       *honeyd.Server
	Registry   *drivers.Registry
	Dispatcher *alert.Dispatcher
	Tokens     *tokens.Store
	// RunningConfig is what the process started with, so a plan can report the
	// settings an apply cannot change.
	RunningConfig *config.Config
	// Apply reconciles the farm with a new listener set. It is supplied by the
	// caller because applying needs runtime options the API does not own.
	Apply func(listeners []honeyd.ListenerConfig) (added, removed []string, err error)
	// Presence is the overlay hub, when one is configured.
	Presence *presence.Hub
	// VMs provisions full-OS decoys, when the deployment declares any.
	VMs *farm.Provisioner
	// Observer watches inside full-OS decoys from the hypervisor.
	Observer  drivers.ObserverDriver
	Tenant    string
	Site      string
	StartedAt time.Time
	Log       *slog.Logger
	// Token, when set, is required as a Bearer token.
	Token string
}

// Server is the HTTP API.
type Server struct {
	deps Deps
	mux  *http.ServeMux
	http *http.Server
}

// New builds the API server.
func New(addr string, deps Deps) (*Server, error) {
	if deps.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &Server{deps: deps, mux: http.NewServeMux()}
	s.routes()

	s.http = &http.Server{
		Addr:              addr,
		Handler:           s.middleware(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.health)
	s.mux.HandleFunc("GET /api/stats", s.stats)
	s.mux.HandleFunc("GET /api/events", s.events)
	s.mux.HandleFunc("GET /api/events/{uid}", s.eventByUID)
	s.mux.HandleFunc("GET /api/engagements", s.engagements)
	s.mux.HandleFunc("GET /api/engagements/{id}", s.engagementByID)
	s.mux.HandleFunc("GET /api/engagements/{id}/events", s.engagementEvents)
	s.mux.HandleFunc("GET /api/engagements/{id}/forge", s.forgeEngagement)
	s.mux.HandleFunc("GET /api/decoys", s.decoys)
	s.mux.HandleFunc("GET /api/drivers", s.driversList)
	s.mux.HandleFunc("POST /api/evidence/verify", s.verify)
	s.mux.HandleFunc("POST /api/assure", s.runAssurance)
	s.mux.HandleFunc("POST /api/assure/fingerprint", s.runFingerprint)
	s.mux.HandleFunc("GET /api/presence", s.presenceAgents)
	s.mux.HandleFunc("GET /api/economics", s.economics)
	s.mux.HandleFunc("GET /api/vms", s.vmList)
	s.mux.HandleFunc("POST /api/vms/{id}/burn", s.vmBurn)
	s.mux.HandleFunc("POST /api/vms/{id}/revert", s.vmRevert)
	s.mux.HandleFunc("GET /api/config", s.currentConfig)
	s.mux.HandleFunc("POST /api/config/plan", s.planConfig)
	s.mux.HandleFunc("POST /api/config/apply", s.applyConfig)
	s.mux.HandleFunc("GET /api/tokens", s.listTokens)
	s.mux.HandleFunc("POST /api/tokens", s.mintToken)
	s.mux.HandleFunc("DELETE /api/tokens/{id}", s.deleteToken)
	s.mux.HandleFunc("GET /api/tokens/{id}/docx", s.tokenDocx)
	s.mux.HandleFunc("GET /api/compliance/{framework}", s.complianceReport)
	s.mux.HandleFunc("GET /api/graph", s.graphAnalysis)
	s.mux.HandleFunc("GET /api/topology", s.topology)
	s.mux.HandleFunc("POST /api/vms/{id}/start", s.vmStart)
	s.mux.HandleFunc("POST /api/vms/{id}/stop", s.vmStop)
	s.mux.HandleFunc("POST /api/fingerprint", s.runFingerprint)
	s.mux.HandleFunc("GET /api/system", s.systemInfo)
	s.mux.HandleFunc("GET /api/observer", s.observerStatus)
	s.mux.HandleFunc("POST /api/observer/{id}/dump", s.observerDump)

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("api: embedded UI missing: " + err.Error())
	}
	s.mux.Handle("GET /", http.FileServer(http.FS(sub)))
}

// middleware applies auth, security headers and request logging.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The UI renders attacker-controlled strings (commands, user agents,
		// payloads). A strict CSP means a stored payload cannot become a
		// cross-site scripting bug in the console an analyst uses.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if s.deps.Token != "" && !strings.HasPrefix(r.URL.Path, "/api/health") {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.deps.Token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins serving. It returns once the listener is up.
func (s *Server) Start() error {
	go func() {
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.deps.Log.Error("api server stopped", "err", err)
		}
	}()
	return nil
}

// Shutdown stops the API.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

// Handler exposes the router, for tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		// The status line is already written; there is nothing useful left to
		// say to the client.
		return
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"product": version.Product,
		"version": version.Version,
		"uptime":  time.Since(s.deps.StartedAt).Round(time.Second).String(),
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	active, closed := 0, 0
	if s.deps.Tracker != nil {
		active, closed = s.deps.Tracker.Stats()
	}
	sent, suppressed, failed := uint64(0), uint64(0), uint64(0)
	if s.deps.Dispatcher != nil {
		sent, suppressed, failed = s.deps.Dispatcher.Stats()
	}
	sessions := 0
	if s.deps.Farm != nil {
		sessions = s.deps.Farm.ActiveSessions()
	}
	tokenTotal, tokenFired := 0, 0
	if s.deps.Tokens != nil {
		tokenTotal, tokenFired = s.deps.Tokens.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": s.deps.Tenant, "site": s.deps.Site,
		"tokens":  map[string]int{"total": tokenTotal, "triggered": tokenFired},
		"version": version.String(),
		"uptime":  time.Since(s.deps.StartedAt).Round(time.Second).String(),
		"storage": s.deps.Store.Stats(),
		"engagements": map[string]int{
			"active": active, "closed": closed,
		},
		"alerts": map[string]uint64{
			"sent": sent, "suppressed": suppressed, "failed": failed,
		},
		"live_sessions": sessions,
	})
}

// parseQuery turns URL parameters into a store query, ignoring what it cannot
// understand rather than failing: a UI should never 400 because of a stale
// bookmark.
func parseQuery(r *http.Request) store.Query {
	q := store.Query{Limit: 100}
	v := r.URL.Query()

	if n, err := strconv.Atoi(v.Get("limit")); err == nil && n > 0 && n <= 2000 {
		q.Limit = n
	}
	if n, err := strconv.Atoi(v.Get("offset")); err == nil && n >= 0 {
		q.Offset = n
	}
	q.Service = v.Get("service")
	q.DecoyID = v.Get("decoy")
	q.EngagementID = v.Get("engagement")
	q.SrcIP = v.Get("src")
	q.Search = v.Get("q")
	if p := v.Get("plane"); p != "" {
		q.Plane = event.Plane(p)
	}
	if s := v.Get("severity"); s != "" {
		switch strings.ToLower(s) {
		case "low":
			q.MinSeverity = event.SeverityLow
		case "medium":
			q.MinSeverity = event.SeverityMedium
		case "high":
			q.MinSeverity = event.SeverityHigh
		case "critical":
			q.MinSeverity = event.SeverityCritical
		}
	}
	if mins, err := strconv.Atoi(v.Get("since_minutes")); err == nil && mins > 0 {
		q.Since = time.Now().Add(-time.Duration(mins) * time.Minute)
	}
	return q
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	evs, err := s.deps.Store.Query(r.Context(), parseQuery(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "count": len(evs)})
}

func (s *Server) eventByUID(w http.ResponseWriter, r *http.Request) {
	e, err := s.deps.Store.Get(r.Context(), r.PathValue("uid"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such event"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) engagements(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tracker == nil {
		writeJSON(w, http.StatusOK, map[string]any{"engagements": []any{}})
		return
	}
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	list := s.deps.Tracker.Recent(limit)
	writeJSON(w, http.StatusOK, map[string]any{"engagements": list, "count": len(list)})
}

func (s *Server) engagementByID(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tracker == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no tracker"})
		return
	}
	e, ok := s.deps.Tracker.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such engagement"})
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// engagementEvents returns one engagement's full timeline, oldest first. This
// is the view an analyst reads top to bottom.
func (s *Server) engagementEvents(w http.ResponseWriter, r *http.Request) {
	q := parseQuery(r)
	q.EngagementID = r.PathValue("id")
	q.Ascending = true
	if q.Limit < 500 {
		q.Limit = 500
	}
	evs, err := s.deps.Store.Query(r.Context(), q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "count": len(evs)})
}

// forgeEngagement turns one engagement into detection content for the real
// network: Sigma, Suricata, YARA, a STIX bundle and an incident report.
func (s *Server) forgeEngagement(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	evs, err := s.deps.Store.Query(r.Context(), store.Query{
		EngagementID: id, Ascending: true, Limit: 5000,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(evs) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no events for that engagement"})
		return
	}

	eng, ok := (*engagement.Engagement)(nil), false
	if s.deps.Tracker != nil {
		eng, ok = s.deps.Tracker.Get(id)
	}
	if !ok {
		// Rebuild from the evidence: an engagement that has aged out of the
		// tracker must still be reportable.
		if rebuilt := engagement.FromEvents(evs); len(rebuilt) > 0 {
			eng = rebuilt[0]
		} else {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such engagement"})
			return
		}
	}

	bundle := forge.New().Build(eng, evs)

	switch r.URL.Query().Get("format") {
	case "sigma", "suricata", "yara":
		f := forge.Format(r.URL.Query().Get("format"))
		var b strings.Builder
		for _, rule := range bundle.RulesOf(f) {
			b.WriteString(rule.Content)
			if !strings.HasSuffix(rule.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
		writeText(w, b.String())
	case "stix":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(bundle.STIX))
	case "report":
		writeText(w, bundle.Report)
	default:
		writeJSON(w, http.StatusOK, bundle)
	}
}

func writeText(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(s))
}

// runAssurance attacks the deployment with harmless probes and reports whether
// each one produced the evidence it should have.
//
// It is a POST because it is an action with side effects -- traffic against the
// decoys and events in the evidence chain -- not something a page refresh
// should trigger.
func (s *Server) runAssurance(w http.ResponseWriter, r *http.Request) {
	if s.deps.Farm == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no decoy farm"})
		return
	}
	targets := map[string]string{}
	for _, l := range s.deps.Farm.Bound() {
		if l.Proto != "tcp" {
			continue
		}
		// Probe loopback: the bind address may be a wildcard.
		_, port, err := net.SplitHostPort(l.Address)
		if err != nil {
			continue
		}
		if _, taken := targets[l.Service]; !taken {
			targets[l.Service] = net.JoinHostPort("127.0.0.1", port)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	runner := &assure.Runner{Targets: targets, Store: s.deps.Store, Timeout: 15 * time.Second}
	report := runner.Run(ctx, assure.DefaultScenarios())

	code := http.StatusOK
	if !report.Healthy {
		// A failing self-test is a real problem with the deployment, and a
		// monitoring system should be able to see it without parsing the body.
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, report)
}

// currentConfig reports what is running, so a manifest can be compared against
// reality rather than against what someone believes is running.
// runFingerprint scores how identifiable each decoy is.
//
// Every deception product claims its decoys are indistinguishable; none of them
// publishes a number. This endpoint is that number, with the specific thing
// that gives each decoy away and what to do about it.
func (s *Server) runFingerprint(w http.ResponseWriter, r *http.Request) {
	if s.deps.Farm == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no decoy farm"})
		return
	}
	personas := s.deps.Farm.Personas()

	byDecoy := map[string]*assure.DecoyProfile{}
	for _, l := range s.deps.Farm.Bound() {
		if l.Proto != "tcp" {
			continue
		}
		prof, ok := byDecoy[l.DecoyID]
		if !ok {
			prof = &assure.DecoyProfile{
				DecoyID: l.DecoyID, Persona: l.Persona,
				Endpoints: map[string]string{},
			}
			if p := personas[l.Persona]; p != nil {
				history, logs := p.Liveness()
				prof.Hostname, prof.OS = p.Hostname, p.OSName
				prof.UptimeDays = time.Since(p.BootTime).Hours() / 24
				prof.HistoryBytes, prof.LogLines = history, logs
			}
			byDecoy[l.DecoyID] = prof
		}
		_, port, err := net.SplitHostPort(l.Address)
		if err != nil {
			continue
		}
		if _, taken := prof.Endpoints[l.Service]; !taken {
			prof.Endpoints[l.Service] = net.JoinHostPort("127.0.0.1", port)
		}
	}

	profiles := make([]assure.DecoyProfile, 0, len(byDecoy))
	for _, p := range byDecoy {
		profiles = append(profiles, *p)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	fp := &assure.Fingerprinter{Timeout: 5 * time.Second}
	writeJSON(w, http.StatusOK, fp.Run(ctx, profiles))
}

// presenceAgents reports the overlay agents currently connected.
func (s *Server) presenceAgents(w http.ResponseWriter, r *http.Request) {
	if s.deps.Presence == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "agents": []any{}})
		return
	}
	agents := s.deps.Presence.Agents()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "hub": s.deps.Presence.Addr(),
		"agents": agents, "connected": len(agents),
	})
}

func (s *Server) economics(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tracker == nil {
		writeJSON(w, http.StatusOK, engagement.Economics{})
		return
	}
	econ := s.deps.Tracker.Economics()
	writeJSON(w, http.StatusOK, econ)
}

func (s *Server) vmList(w http.ResponseWriter, r *http.Request) {
	if s.deps.VMs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "decoys": []any{}})
		return
	}
	st := s.deps.VMs.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "decoys": st, "count": len(st),
		"can_revert": s.deps.VMs.CanRevert(),
	})
}

// vmBurn takes a decoy out of service and preserves it.
//
// This is the button an analyst reaches for when the evidence says the machine
// is owned. It is deliberately not automatic: deciding that an intrusion has
// gone far enough to sacrifice a decoy is a judgement, and a platform that made
// it on its own would eventually make it during a penetration test.
func (s *Server) vmBurn(w http.ResponseWriter, r *http.Request) {
	s.vmAction(w, r, "burn")
}

// vmRevert resets a decoy to its baseline, keeping the dirty state as evidence.
func (s *Server) vmRevert(w http.ResponseWriter, r *http.Request) {
	s.vmAction(w, r, "revert")
}

func (s *Server) vmAction(w http.ResponseWriter, r *http.Request, action string) {
	if s.deps.VMs == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "this deployment has no full-OS decoys"})
		return
	}
	id := r.PathValue("id")
	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if body.Reason == "" {
		body.Reason = "requested by an operator"
	}

	var err error
	switch action {
	case "burn":
		err = s.deps.VMs.Burn(r.Context(), id, body.Reason)
	case "revert":
		err = s.deps.VMs.Revert(r.Context(), id, body.Reason)
	case "start":
		err = s.deps.VMs.Start(r.Context(), id)
	case "stop":
		err = s.deps.VMs.Stop(r.Context(), id)
	}
	if errors.Is(err, farm.ErrNotProvisioned) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "action": action, "reason": body.Reason})
}

func (s *Server) currentConfig(w http.ResponseWriter, r *http.Request) {
	if s.deps.Farm == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no decoy farm"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":    s.deps.Tenant,
		"site":      s.deps.Site,
		"listeners": s.deps.Farm.Listeners(),
		"bound":     s.deps.Farm.Bound(),
	})
}

// planConfig shows what applying a manifest would do, without doing it.
func (s *Server) planConfig(w http.ResponseWriter, r *http.Request) {
	desired, plan, err := s.buildPlan(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = desired
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": plan, "summary": plan.Summary(), "applied": false,
	})
}

// applyConfig reconciles the running farm with a manifest.
func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request) {
	desired, plan, err := s.buildPlan(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.deps.Apply == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "this deployment does not support applying configuration"})
		return
	}
	added, removed, err := s.deps.Apply(desired.Listeners())
	if err != nil {
		// Reconcile validates the whole set before touching anything, so a
		// failure here means nothing changed.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(), "applied": false, "plan": plan,
		})
		return
	}
	s.deps.Log.Info("configuration applied",
		"added", len(added), "removed", len(removed), "unchanged", plan.Unchanged)
	writeJSON(w, http.StatusOK, map[string]any{
		"plan": plan, "summary": plan.Summary(), "applied": true,
		"added": added, "removed": removed,
	})
}

// buildPlan parses a manifest from the request body and diffs it against what
// is running.
func (s *Server) buildPlan(r *http.Request) (*config.Config, config.Plan, error) {
	if s.deps.Farm == nil {
		return nil, config.Plan{}, errors.New("no decoy farm")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		return nil, config.Plan{}, err
	}
	desired, err := config.Parse(raw)
	if err != nil {
		return nil, config.Plan{}, err
	}
	plan := config.DiffListeners(s.deps.Farm.Listeners(), desired.Listeners(), desired.Honeyd.Bind)
	if s.deps.RunningConfig != nil {
		plan.RequiresRestart = config.Immutable(s.deps.RunningConfig, desired)
	}
	return desired, plan, nil
}

func (s *Server) decoys(w http.ResponseWriter, r *http.Request) {
	type decoyView struct {
		Persona  string `json:"persona"`
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Uptime   string `json:"uptime_days"`
		Users    int    `json:"users"`
	}
	out := map[string]decoyView{}
	if s.deps.Farm != nil {
		for name, p := range s.deps.Farm.Personas() {
			out[name] = decoyView{
				Persona: name, Hostname: p.Hostname, OS: p.OSName,
				Uptime: fmt.Sprintf("%.0f", time.Since(p.BootTime).Hours()/24),
				Users:  len(p.Users),
			}
		}
	}
	listeners := []string{}
	if s.deps.Farm != nil {
		listeners = s.deps.Farm.Addrs()
	}
	// Distinct addresses is the number an operator asks for: how much of the
	// segment does this deployment actually occupy?
	addrs := map[string]bool{}
	for _, l := range listeners {
		if host, _, err := net.SplitHostPort(l); err == nil {
			addrs[host] = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"personas": out, "listeners": listeners, "projected_addresses": len(addrs),
		"bound": func() any {
			if s.deps.Farm == nil {
				return []any{}
			}
			return s.deps.Farm.Bound()
		}(),
	})
}

func (s *Server) driversList(w http.ResponseWriter, r *http.Request) {
	if s.deps.Registry == nil {
		writeJSON(w, http.StatusOK, map[string]any{"drivers": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drivers": s.deps.Registry.Available()})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tokens == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tokens": []any{}})
		return
	}
	list := s.deps.Tokens.List()
	total, triggered := s.deps.Tokens.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens": list, "total": total, "triggered": triggered, "types": tokens.AllTypes(),
	})
}

func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tokens == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tokens are not configured"})
		return
	}
	var req struct {
		Type     string `json:"type"`
		Label    string `json:"label"`
		Location string `json:"location"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	t, err := s.deps.Tokens.Mint(tokens.Type(req.Type), req.Label, req.Location)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tokens == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tokens are not configured"})
		return
	}
	if err := s.deps.Tokens.Delete(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tokenDocx builds the bait document for a token, ready to be planted.
func (s *Server) tokenDocx(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tokens == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tokens are not configured"})
		return
	}
	t, ok := s.deps.Tokens.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such token"})
		return
	}
	title := t.Label
	if title == "" {
		title = "Confidential"
	}
	doc, err := tokens.GenerateDocx(t, title,
		"This document is confidential and intended for internal use only.")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", `attachment; filename="`+t.ID+`.docx"`)
	w.Write(doc)
}

// verify replays the durable hash chain. It is the operation an analyst runs
// before exporting evidence, and it is intentionally a POST: on a large store
// it is expensive, and it should not be triggered by a page refresh.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	err := s.deps.Store.Verify(r.Context())
	st := s.deps.Store.Stats()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false, "error": err.Error(),
			"events": st.Events, "took": time.Since(start).String(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true, "events": st.Events,
		"head_seq": st.HeadSeq, "head_hash": st.HeadHash,
		"took": time.Since(start).Round(time.Millisecond).String(),
	})
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

// complianceReport generates an audit report for one regulatory framework.
//
// Frameworks: nis2, dora, iso27001, pci, soc2, iec62443.
// Returns the controls, their satisfaction status, and a coverage percentage.
func (s *Server) complianceReport(w http.ResponseWriter, r *http.Request) {
	fw := r.PathValue("framework")

	// Map URL slugs to the framework names the compliance package uses.
	allowed := map[string]string{
		"nis2":     "NIS2",
		"dora":     "DORA",
		"iso27001": "ISO 27001:2022",
		"pci":      "PCI DSS 4.0",
		"soc2":     "SOC 2",
		"iec62443": "IEC 62443",
	}
	canonical, ok := allowed[fw]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown framework: " + fw + "; supported: nis2, dora, iso27001, pci, soc2, iec62443",
		})
		return
	}

	cap := s.buildCapabilities()
	all := compliance.Audit(cap)

	// Filter to the requested framework.
	var controls []compliance.Control
	for _, c := range all {
		if c.Framework == canonical {
			controls = append(controls, c)
		}
	}

	passed := 0
	for _, c := range controls {
		if c.Satisfied {
			passed++
		}
	}
	var coverage float64
	if len(controls) > 0 {
		coverage = float64(passed) / float64(len(controls)) * 100
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"framework": canonical,
		"controls":  controls,
		"passed":    passed,
		"total":     len(controls),
		"coverage":  coverage,
	})
}

// buildCapabilities inspects the running deployment to build the capability
// descriptor the compliance package needs.
func (s *Server) buildCapabilities() compliance.Capabilities {
	cap := compliance.Capabilities{
		HasHashChain: true, // the store is always an append-only hash chain
	}
	if s.deps.Farm != nil {
		bound := s.deps.Farm.Bound()
		cap.HasDecoys = len(bound) > 0
		cap.DecoyCount = len(bound)
		// Check for specific protocol capabilities.
		for _, l := range bound {
			switch l.Service {
			case "kerberos":
				cap.HasKerberos = true
			}
		}
		cap.HasRansomware = true // the FTP service includes the ransomware engine
	}
	if s.deps.Tracker != nil {
		active, closed := s.deps.Tracker.Stats()
		cap.HasEngagements = true
		cap.EngagementCount = active + closed
		cap.HasEconomics = true
	}
	if s.deps.Dispatcher != nil {
		cap.HasAlerts = true
		sent, _, _ := s.deps.Dispatcher.Stats()
		cap.AlertCount = int(sent)
	}
	if s.deps.Tokens != nil {
		cap.HasTokens = true
		cap.HasBreadcrumbs = true
	}
	if s.deps.Presence != nil {
		cap.HasOverlay = true
	}
	if s.deps.VMs != nil {
		cap.HasVMFarm = true
	}
	// Forge and assure are always available when the binary is running.
	cap.HasForge = true
	cap.HasAssure = s.deps.Farm != nil
	cap.HasFingerprint = s.deps.Farm != nil

	if s.deps.Registry != nil {
		for _, info := range s.deps.Registry.Available() {
			if info.Kind == drivers.KindSink {
				cap.SinkCount++
			}
			if info.Kind == drivers.KindFabric {
				cap.FabricDriver = info.Name
			}
		}
	}

	st := s.deps.Store.Stats()
	cap.EvidenceFile = fmt.Sprintf("%d events, head seq %d", st.Events, st.HeadSeq)
	cap.DeploymentDate = s.deps.StartedAt
	return cap
}

// ---------------------------------------------------------------------------
// Graph — attack path analysis
// ---------------------------------------------------------------------------

// graphAnalysis computes attack path coverage from the estate model.
//
// The graph is POSTed as JSON in the request body when the operator wants to
// analyze a specific topology. A GET with no body returns an empty analysis
// with instructions.
func (s *Server) graphAnalysis(w http.ResponseWriter, r *http.Request) {
	// The graph is built from a manifest the operator uploads, not from live
	// scanning (see package graph doc). Accept it as a query parameter pointing
	// to a pre-loaded estate, or from the request body for ad-hoc analysis.
	//
	// For a GET endpoint, accept the estate as a JSON query parameter or return
	// an empty scaffold when nothing is supplied.

	estate := r.URL.Query().Get("estate")
	if estate == "" {
		// Return the current deployment's decoy info so the UI can build
		// a partial graph.
		var decoyNodes []graph.Node
		var decoys []graph.Decoy
		if s.deps.Farm != nil {
			for _, l := range s.deps.Farm.Bound() {
				decoyNodes = append(decoyNodes, graph.Node{
					ID:   l.DecoyID,
					Type: "server",
					Tags: map[string]string{"service": l.Service, "persona": l.Persona},
				})
				decoys = append(decoys, graph.Decoy{
					ID:      l.DecoyID,
					AtNode:  l.DecoyID,
					Service: l.Service,
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":     "supply an estate model as JSON to /api/graph via POST, or use the query parameter 'estate'",
			"decoy_nodes": decoyNodes,
			"decoys":      decoys,
		})
		return
	}

	var e graph.Estate
	if err := json.Unmarshal([]byte(estate), &e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid estate JSON: " + err.Error()})
		return
	}

	g, err := graph.Build(e)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cov := g.Analyze()
	suggestions := g.Suggest(5)

	writeJSON(w, http.StatusOK, map[string]any{
		"coverage":    cov,
		"suggestions": suggestions,
		"nodes":       e.Nodes,
		"edges":       e.Edges,
		"decoys":      e.Decoys,
	})
}

// ---------------------------------------------------------------------------
// Topology — network topology for visualization
// ---------------------------------------------------------------------------

// topology builds a network topology view from the running deployment's state:
// decoys, VMs, presence agents, and the hub.
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	type topoNode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"` // "decoy", "vm", "agent", "hub", "director"
		Group string `json:"group,omitempty"`
		IP    string `json:"ip,omitempty"`
	}
	type topoEdge struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Label   string `json:"label,omitempty"`
		Service string `json:"service,omitempty"`
	}

	var nodes []topoNode
	var edges []topoEdge

	// The director is the center of the star.
	nodes = append(nodes, topoNode{
		ID: "director", Label: "MIRAGE Director", Type: "director",
	})

	// Decoys from the farm.
	seen := map[string]bool{}
	if s.deps.Farm != nil {
		for _, l := range s.deps.Farm.Bound() {
			if seen[l.DecoyID] {
				// Already added as a node; just add another service edge.
				edges = append(edges, topoEdge{
					From: "director", To: l.DecoyID,
					Service: l.Service, Label: l.Service,
				})
				continue
			}
			seen[l.DecoyID] = true
			host, _, _ := net.SplitHostPort(l.Address)
			nodes = append(nodes, topoNode{
				ID: l.DecoyID, Label: l.DecoyID,
				Type: "decoy", Group: l.Persona, IP: host,
			})
			edges = append(edges, topoEdge{
				From: "director", To: l.DecoyID,
				Service: l.Service, Label: l.Service,
			})
		}
	}

	// Full-OS VM decoys.
	if s.deps.VMs != nil {
		for _, vm := range s.deps.VMs.Status() {
			id := "vm:" + vm.ID
			ip := ""
			if len(vm.IPs) > 0 {
				ip = vm.IPs[0]
			}
			nodes = append(nodes, topoNode{
				ID: id, Label: vm.ID,
				Type: "vm", Group: vm.Persona, IP: ip,
			})
			edges = append(edges, topoEdge{
				From: "director", To: id, Label: vm.State,
			})
		}
	}

	// Presence overlay agents.
	if s.deps.Presence != nil {
		nodes = append(nodes, topoNode{
			ID: "hub", Label: "Presence Hub", Type: "hub",
			IP: s.deps.Presence.Addr(),
		})
		edges = append(edges, topoEdge{
			From: "director", To: "hub", Label: "overlay",
		})
		for _, a := range s.deps.Presence.Agents() {
			id := "agent:" + a.ID
			nodes = append(nodes, topoNode{
				ID: id, Label: a.ID, Type: "agent",
			})
			edges = append(edges, topoEdge{
				From: "hub", To: id, Label: "tunnel",
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "edges": edges,
		"count_nodes": len(nodes), "count_edges": len(edges),
	})
}

// ---------------------------------------------------------------------------
// VM start / stop
// ---------------------------------------------------------------------------

func (s *Server) vmStart(w http.ResponseWriter, r *http.Request) {
	s.vmAction(w, r, "start")
}

func (s *Server) vmStop(w http.ResponseWriter, r *http.Request) {
	s.vmAction(w, r, "stop")
}

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

// systemInfo returns system-level details for the operator dashboard: version,
// uptime, runtime, driver registry, and evidence chain stats.
func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	// Driver registry status.
	var driverList []map[string]any
	if s.deps.Registry != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		probeResults := s.deps.Registry.ProbeAll(ctx)
		for _, info := range s.deps.Registry.Available() {
			key := string(info.Kind) + ":" + info.Name
			status := "ok"
			errStr := ""
			if err, probed := probeResults[key]; probed && err != nil {
				status = "error"
				errStr = err.Error()
			}
			entry := map[string]any{
				"name":         info.Name,
				"kind":         info.Kind,
				"summary":      info.Summary,
				"capabilities": info.Capabilities,
				"experimental": info.Experimental,
				"probe_status": status,
			}
			if errStr != "" {
				entry["probe_error"] = errStr
			}
			driverList = append(driverList, entry)
		}
	}

	// Evidence chain stats.
	st := s.deps.Store.Stats()

	writeJSON(w, http.StatusOK, map[string]any{
		"product":    version.Product,
		"version":    version.Version,
		"commit":     version.Commit,
		"build_date": version.BuildDate,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"uptime":     time.Since(s.deps.StartedAt).Round(time.Second).String(),
		"started_at": s.deps.StartedAt.UTC().Format(time.RFC3339),
		"tenant":     s.deps.Tenant,
		"site":       s.deps.Site,
		"drivers":    driverList,
		"evidence":   st,
		"num_cpus":   runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
	})
}

// observerStatus reports the observer driver's status and capabilities.
func (s *Server) observerStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Observer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"driver":     "none",
			"message":    "no observer driver configured; VM decoys run without inside-the-guest observation",
		})
		return
	}
	info := s.deps.Observer.Info()
	probErr := ""
	if err := s.deps.Observer.Probe(r.Context()); err != nil {
		probErr = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":   true,
		"driver":       info.Name,
		"capabilities": info.Capabilities,
		"experimental": info.Experimental,
		"probe_error":  probErr,
		"summary":      info.Summary,
	})
}

// observerDump triggers a memory dump of a VM decoy.
func (s *Server) observerDump(w http.ResponseWriter, r *http.Request) {
	if s.deps.Observer == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "no observer driver configured",
		})
		return
	}
	id := r.PathValue("id")
	outPath := filepath.Join(s.deps.RunningConfig.DataDir, "dumps", id+"-"+time.Now().Format("20060102-150405")+".raw")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := s.deps.Observer.DumpMemory(r.Context(), id, outPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decoy": id,
		"path":  outPath,
	})
}
