package api

import (
	"context"
	"io"
	"net/http"

	"github.com/sauron666/Honeypot/internal/analyst"
	"github.com/sauron666/Honeypot/internal/bec"
	"github.com/sauron666/Honeypot/internal/feed"
	"github.com/sauron666/Honeypot/internal/honeyd"
	"github.com/sauron666/Honeypot/internal/packs"
	"github.com/sauron666/Honeypot/internal/saasid"
	"github.com/sauron666/Honeypot/internal/wireless"
)

// This file exposes the deception-content and threat-intel capabilities to the
// operator console: Deception Packs, SaaS/identity and BEC honey identities, the
// offline analyst, the anonymized feed, and BYOD honey devices. They are
// read-mostly; the one action (bec analyze) takes a pasted message and returns
// its campaign infrastructure. Nothing here mutates a running deployment.

// packsList returns the built-in Deception Packs.
func (s *Server) packsList(w http.ResponseWriter, r *http.Request) {
	all, err := packs.Builtin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type row struct {
		Name, Version, Vertical, Locale string
		Decoys, Tokens                  int
		Valid                           bool
	}
	out := make([]row, 0, len(all))
	for _, p := range all {
		out = append(out, row{
			Name: p.Name, Version: p.Version, Vertical: p.Vertical, Locale: p.Locale,
			Decoys: len(p.Decoys), Tokens: len(p.Honeytokens),
			Valid: p.Validate(personaExists) == nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": out})
}

// packDetail returns one pack in full, plus the YAML fragment an operator would
// paste under honeyd.decoys to apply it (so the GUI can show "how to apply").
func (s *Server) packDetail(w http.ResponseWriter, r *http.Request) {
	p, ok := packs.BuiltinByName(r.PathValue("name"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no pack " + r.PathValue("name")})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pack":    p,
		"summary": p.Summary(),
		"valid":   p.Validate(personaExists) == nil,
	})
}

// personaExists is the persona checker, so pack validation reflects the
// personas this deployment actually knows.
func personaExists(name string) bool {
	for _, n := range honeyd.PersonaNames() {
		if n == name {
			return true
		}
	}
	return false
}

func (s *Server) saasidKit(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "entra"
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = s.deps.Site + ".corp.local"
	}
	k := saasid.Generate(saasid.Provider(provider), domain)
	writeJSON(w, http.StatusOK, map[string]any{"kit": k, "watch": k.WatchList()})
}

func (s *Server) becKit(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = s.deps.Site + ".corp.local"
	}
	k := bec.Generate(domain)
	writeJSON(w, http.StatusOK, map[string]any{"kit": k, "watch": k.WatchAddresses()})
}

// becAnalyze parses a pasted raw email and returns the campaign infrastructure.
func (s *Server) becAnalyze(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read error"})
		return
	}
	c, err := bec.AnalyzeEmail(string(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) wirelessDevices(w http.ResponseWriter, r *http.Request) {
	devs := wireless.DefaultHoneyDevices()
	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devs,
		"browse":  wireless.BrowseNames(devs),
		"note":    wireless.LiveAdvertising(),
	})
}

// analystNarrative summarises one engagement with the OFFLINE template analyst.
// The GUI never drives a live LLM (that is a CLI/operator choice); the template
// gives a deterministic, review-marked narrative safe to show in the console.
func (s *Server) analystNarrative(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tracker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no engagement tracker"})
		return
	}
	eng, ok := s.deps.Tracker.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no engagement " + r.PathValue("id")})
		return
	}
	n, _ := analyst.Template{}.Analyze(context.Background(), *eng)
	writeJSON(w, http.StatusOK, n)
}

// feedPreview returns the anonymized TTP entries the deployment WOULD share.
// It is a preview: nothing is published, and it proves — in the console — that
// no IPs, tenants or tokens leave. Signing happens in the CLI export.
func (s *Server) feedPreview(w http.ResponseWriter, r *http.Request) {
	if s.deps.Tracker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no engagement tracker"})
		return
	}
	salt := r.URL.Query().Get("salt")
	if salt == "" {
		salt = s.deps.Tenant + "/" + s.deps.Site
	}
	var entries []feed.Entry
	for _, e := range s.deps.Tracker.Recent(500) {
		entries = append(entries, feed.Anonymize(*e, salt))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"note":    "anonymized preview — no IPs/tenant/site/tokens included; sign & publish via `miragectl feed export`",
	})
}
