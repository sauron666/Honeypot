package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/alert"
	"github.com/sauron666/Honeypot/internal/driverset"
	"github.com/sauron666/Honeypot/internal/event"
)

func serverWithAlerting(t *testing.T) *Server {
	t.Helper()
	d := alert.NewDispatcher(alert.Options{MinSeverity: event.SeverityHigh})
	srv, err := New(":0", Deps{
		Store:      &stubStore{},
		Dispatcher: d,
		Registry:   driverset.Default(),
		StartedAt:  time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestSinksListAndThreshold(t *testing.T) {
	srv := serverWithAlerting(t)
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/sinks", ""))
	if m["min_severity"] != "high" {
		t.Fatalf("default threshold = %v, want high", m["min_severity"])
	}
	if av, ok := m["available"].([]any); !ok || len(av) == 0 {
		t.Fatalf("expected available sink drivers, got %v", m["available"])
	}
	// Change the threshold live.
	rec := doBody(srv.Handler(), "POST", "/api/sinks/severity", "", `{"min_severity":"low"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set severity: %d %s", rec.Code, rec.Body.String())
	}
	m = jsonBody(t, do(srv.Handler(), "GET", "/api/sinks", ""))
	if m["min_severity"] != "low" {
		t.Fatalf("threshold not updated: %v", m["min_severity"])
	}
	if rec := doBody(srv.Handler(), "POST", "/api/sinks/severity", "", `{"min_severity":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad severity should be 400, got %d", rec.Code)
	}
}

func TestSinkAddTestRemove(t *testing.T) {
	srv := serverWithAlerting(t)
	// Add a stdout sink (always reachable, no config).
	if rec := doBody(srv.Handler(), "POST", "/api/sinks", "", `{"driver":"stdout"}`); rec.Code != http.StatusOK {
		t.Fatalf("add stdout sink: %d %s", rec.Code, rec.Body.String())
	}
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/sinks", ""))
	sinks, _ := m["sinks"].([]any)
	if len(sinks) != 1 {
		t.Fatalf("expected 1 sink, got %v", m["sinks"])
	}
	// Test delivery reaches it.
	tm := jsonBody(t, doBody(srv.Handler(), "POST", "/api/sinks/test", "", ""))
	res, _ := tm["results"].([]any)
	if len(res) != 1 {
		t.Fatalf("expected 1 test result, got %v", tm["results"])
	}
	// Remove it.
	if rec := do(srv.Handler(), "DELETE", "/api/sinks/0", ""); rec.Code != http.StatusOK {
		t.Fatalf("remove sink: %d", rec.Code)
	}
	if rec := do(srv.Handler(), "DELETE", "/api/sinks/0", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("removing a gone sink should be 404, got %d", rec.Code)
	}
	// An unknown driver is a 400, not a panic.
	if rec := doBody(srv.Handler(), "POST", "/api/sinks", "", `{"driver":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown sink driver should be 400, got %d", rec.Code)
	}
}
