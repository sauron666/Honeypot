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
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/assure"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/forge"
	"github.com/sauron666/Honeypot/internal/honeyd"
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
	Tenant     string
	Site       string
	StartedAt  time.Time
	Log        *slog.Logger
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
	s.mux.HandleFunc("GET /api/tokens", s.listTokens)
	s.mux.HandleFunc("POST /api/tokens", s.mintToken)
	s.mux.HandleFunc("DELETE /api/tokens/{id}", s.deleteToken)
	s.mux.HandleFunc("GET /api/tokens/{id}/docx", s.tokenDocx)

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
