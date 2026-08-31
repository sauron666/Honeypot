package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// This file makes alert delivery configurable from the console at runtime.
// Where alarms go is the product's whole output, and until now changing it
// meant editing the profile and restarting -- the worst time to discover a
// misrouted SIEM is mid-incident. An operator can now list, add, test and
// remove sinks, and tune the severity threshold, live.
//
// Like the decoy builder, these changes are runtime-only: they are NOT written
// back to the profile, so they do not survive a restart. The GUI says so. That
// keeps the profile the single source of truth for a persistent deployment
// while still allowing on-the-spot changes during an incident.

// sinkView is one sink as the console sees it: which driver, a redacted
// summary, never its secrets.
type sinkView struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
}

func (s *Server) sinksList(w http.ResponseWriter, r *http.Request) {
	if s.deps.Dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no alert dispatcher"})
		return
	}
	infos := s.deps.Dispatcher.SinkInfos()
	sinks := make([]sinkView, 0, len(infos))
	for i, in := range infos {
		sinks = append(sinks, sinkView{Index: i, Name: in.Name, Kind: string(in.Kind), Summary: in.Summary})
	}
	// The drivers an operator can add, so the form can populate its dropdown.
	var available []string
	if s.deps.Registry != nil {
		for _, in := range s.deps.Registry.AvailableOf(drivers.KindSink) {
			available = append(available, in.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sinks":        sinks,
		"min_severity": s.deps.Dispatcher.MinSeverity().String(),
		"available":    available,
		"note":         "runtime only — add sinks to the profile to persist them across restarts",
	})
}

// sinkAdd builds a sink from {driver, config} and wires it live. It probes the
// destination first and reports an unreachable one as a warning rather than a
// hard failure, because a sink that is down now may be up during the incident
// -- but the operator is told.
func (s *Server) sinkAdd(w http.ResponseWriter, r *http.Request) {
	if s.deps.Dispatcher == nil || s.deps.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "alerting is not available on this deployment"})
		return
	}
	var body struct {
		Driver string         `json:"driver"`
		Config map[string]any `json:"config"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sink JSON: " + err.Error()})
		return
	}
	if body.Driver == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a sink driver is required"})
		return
	}
	if body.Config == nil {
		body.Config = map[string]any{}
	}
	sink, err := s.deps.Registry.Sink(body.Driver, body.Config)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	warning := ""
	if err := sink.Probe(ctx); err != nil {
		warning = "sink added, but it is not reachable right now: " + err.Error()
	}
	s.deps.Dispatcher.AddSink(sink)
	s.deps.Log.Info("alert sink added from console", "driver", body.Driver)
	writeJSON(w, http.StatusOK, map[string]any{"added": body.Driver, "warning": warning})
}

func (s *Server) sinkRemove(w http.ResponseWriter, r *http.Request) {
	if s.deps.Dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no alert dispatcher"})
		return
	}
	i, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "index must be a number"})
		return
	}
	if !s.deps.Dispatcher.RemoveSinkAt(i) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no sink at that index"})
		return
	}
	s.deps.Log.Info("alert sink removed from console", "index", i)
	writeJSON(w, http.StatusOK, map[string]any{"removed": i})
}

func (s *Server) sinkTest(w http.ResponseWriter, r *http.Request) {
	if s.deps.Dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no alert dispatcher"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	results := s.deps.Dispatcher.SendTest(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) sinkSeverity(w http.ResponseWriter, r *http.Request) {
	if s.deps.Dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no alert dispatcher"})
		return
	}
	var body struct {
		MinSeverity string `json:"min_severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	sev, ok := parseSeverity(body.MinSeverity)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown severity " + body.MinSeverity})
		return
	}
	s.deps.Dispatcher.SetMinSeverity(sev)
	s.deps.Log.Info("alert threshold changed from console", "min_severity", sev.String())
	writeJSON(w, http.StatusOK, map[string]any{"min_severity": sev.String()})
}

func parseSeverity(s string) (event.Severity, bool) {
	switch s {
	case "informational", "info":
		return event.SeverityInformational, true
	case "low":
		return event.SeverityLow, true
	case "medium":
		return event.SeverityMedium, true
	case "high":
		return event.SeverityHigh, true
	case "critical":
		return event.SeverityCritical, true
	case "fatal":
		return event.SeverityFatal, true
	}
	return 0, false
}
