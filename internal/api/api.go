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
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/store"
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
	s.mux.HandleFunc("GET /api/decoys", s.decoys)
	s.mux.HandleFunc("GET /api/drivers", s.driversList)
	s.mux.HandleFunc("POST /api/evidence/verify", s.verify)

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
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": s.deps.Tenant, "site": s.deps.Site,
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
	writeJSON(w, http.StatusOK, map[string]any{"personas": out, "listeners": listeners})
}

func (s *Server) driversList(w http.ResponseWriter, r *http.Request) {
	if s.deps.Registry == nil {
		writeJSON(w, http.StatusOK, map[string]any{"drivers": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drivers": s.deps.Registry.Available()})
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
