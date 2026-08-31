package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/honeyd"
)

// farmWithDecoy builds an unstarted honeyd farm holding one decoy, plus a fake
// Apply that records the last listener set it was handed. That is enough to
// exercise the console's add/remove merge logic without binding real ports.
func farmWithDecoy(t *testing.T) (*honeyd.Server, *[]honeyd.ListenerConfig) {
	t.Helper()
	emit := honeyd.EmitterFunc(func(context.Context, *event.Event) {})
	farm, err := honeyd.NewServer(honeyd.Config{
		BindAddr: "127.0.0.1",
		Listeners: []honeyd.ListenerConfig{
			{Service: "ssh", Port: 22, Persona: "linux/web", DecoyID: "web-1"},
			{Service: "http", Port: 80, Persona: "linux/web", DecoyID: "web-1"},
		},
	}, emit, nil, nil)
	if err != nil {
		t.Fatalf("build farm: %v", err)
	}
	var last []honeyd.ListenerConfig
	return farm, &last
}

func serverWithFarm(t *testing.T) (*Server, *[]honeyd.ListenerConfig) {
	t.Helper()
	farm, last := farmWithDecoy(t)
	srv, err := New(":0", Deps{
		Store:     &stubStore{},
		Farm:      farm,
		StartedAt: time.Now(),
		Tenant:    "t", Site: "s",
		Apply: func(ls []honeyd.ListenerConfig) (added, removed []string, err error) {
			*last = ls
			return nil, nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, last
}

func TestServiceCatalogListsServicesAndPersonas(t *testing.T) {
	srv, _ := serverWithFarm(t)
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/services", ""))
	if svcs, ok := m["services"].([]any); !ok || len(svcs) == 0 {
		t.Fatalf("expected registered services, got %v", m["services"])
	}
	if ps, ok := m["personas"].([]any); !ok || len(ps) == 0 {
		t.Fatalf("expected personas, got %v", m["personas"])
	}
}

func TestAddDecoyMergesWithRunningSet(t *testing.T) {
	srv, last := serverWithFarm(t)
	body := `{"id":"db-1","persona":"linux/db","services":[{"service":"mysql","port":3306}]}`
	rec := doBody(srv.Handler(), "POST", "/api/decoys", "", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("add decoy: %d %s", rec.Code, rec.Body.String())
	}
	// The applied set must keep the existing web-1 decoy and add db-1: an add is
	// a merge, never a replace of the whole farm.
	var haveWeb, haveDB bool
	for _, l := range *last {
		if l.DecoyID == "web-1" {
			haveWeb = true
		}
		if l.DecoyID == "db-1" && l.Service == "mysql" {
			haveDB = true
		}
	}
	if !haveWeb || !haveDB {
		t.Fatalf("expected both web-1 and db-1 in applied set, got %#v", *last)
	}
}

func TestAddDecoyReplacesSameID(t *testing.T) {
	srv, last := serverWithFarm(t)
	body := `{"id":"web-1","persona":"linux/web","services":[{"service":"ssh","port":2222}]}`
	if rec := doBody(srv.Handler(), "POST", "/api/decoys", "", body); rec.Code != http.StatusOK {
		t.Fatalf("edit decoy: %d %s", rec.Code, rec.Body.String())
	}
	// web-1 was ssh:22 + http:80; editing it to ssh:2222 must leave exactly one
	// listener for web-1, on the new port -- not the union of old and new.
	var count, port int
	for _, l := range *last {
		if l.DecoyID == "web-1" {
			count++
			port = l.Port
		}
	}
	if count != 1 || port != 2222 {
		t.Fatalf("expected web-1 replaced by one listener on 2222, got count=%d port=%d", count, port)
	}
}

func TestAddDecoyRejectsUnknownServiceAndPersona(t *testing.T) {
	srv, _ := serverWithFarm(t)
	cases := []string{
		`{"id":"x","persona":"linux/web","services":[{"service":"nope","port":1}]}`,
		`{"id":"x","persona":"no/such","services":[{"service":"ssh","port":22}]}`,
		`{"id":"","persona":"linux/web","services":[{"service":"ssh","port":22}]}`,
		`{"id":"x","persona":"linux/web","services":[]}`,
		`{"id":"x","persona":"linux/web","services":[{"service":"ssh","port":70000}]}`,
	}
	for i, c := range cases {
		if rec := doBody(srv.Handler(), "POST", "/api/decoys", "", c); rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d: expected 400, got %d (%s)", i, rec.Code, rec.Body.String())
		}
	}
}

func TestRemoveDecoy(t *testing.T) {
	srv, last := serverWithFarm(t)
	if rec := do(srv.Handler(), "DELETE", "/api/decoys/web-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("remove decoy: %d %s", rec.Code, rec.Body.String())
	}
	for _, l := range *last {
		if l.DecoyID == "web-1" {
			t.Fatalf("web-1 should be gone from the applied set, got %#v", *last)
		}
	}
	// Removing a decoy that does not exist is a 404, not a silent no-op that
	// would tear the whole farm down to nothing.
	if rec := do(srv.Handler(), "DELETE", "/api/decoys/ghost", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown decoy, got %d", rec.Code)
	}
}

func TestAddDecoyWithoutApplyIsUnavailable(t *testing.T) {
	farm, _ := farmWithDecoy(t)
	srv, err := New(":0", Deps{Store: &stubStore{}, Farm: farm, StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"x","persona":"linux/web","services":[{"service":"ssh","port":22}]}`
	if rec := doBody(srv.Handler(), "POST", "/api/decoys", "", body); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without Apply, got %d", rec.Code)
	}
}
