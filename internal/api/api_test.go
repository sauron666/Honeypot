package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/store"
)

// stubStore satisfies store.EventStore with an in-memory slice.
type stubStore struct {
	events []*event.Event
}

func (s *stubStore) Append(_ context.Context, e *event.Event) error {
	s.events = append(s.events, e)
	return nil
}

func (s *stubStore) Query(_ context.Context, q store.Query) ([]*event.Event, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	end := q.Limit
	if end > len(s.events) {
		end = len(s.events)
	}
	out := make([]*event.Event, end)
	copy(out, s.events[:end])
	return out, nil
}

func (s *stubStore) Get(_ context.Context, uid string) (*event.Event, error) {
	for _, e := range s.events {
		if e.Metadata.UID == uid {
			return e, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *stubStore) Head() (uint64, string) { return 0, "" }

func (s *stubStore) Verify(_ context.Context) error { return nil }

func (s *stubStore) Stats() store.Stats {
	return store.Stats{Events: uint64(len(s.events))}
}

func (s *stubStore) Close() error { return nil }

func newTestServer(t *testing.T, token string) (*Server, *stubStore) {
	t.Helper()
	st := &stubStore{}
	srv, err := New(":0", Deps{
		Store:     st,
		Token:     token,
		StartedAt: time.Now(),
		Tenant:    "test-tenant",
		Site:      "test-site",
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func do(handler http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func doBody(handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, rec.Body.String())
	}
	return m
}

// --- Auth middleware ---

func TestHealthExemptFromAuth(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	rec := do(srv.Handler(), "GET", "/api/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/health should be exempt from auth, got %d", rec.Code)
	}
	m := jsonBody(t, rec)
	if m["status"] != "ok" {
		t.Fatalf("health status: %v", m["status"])
	}
}

func TestAuthRejectsNoToken(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	rec := do(srv.Handler(), "GET", "/api/stats", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestAuthRejectsWrongToken(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	rec := do(srv.Handler(), "GET", "/api/stats", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", rec.Code)
	}
}

func TestAuthAcceptsCorrectToken(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	rec := do(srv.Handler(), "GET", "/api/stats", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", rec.Code)
	}
}

func TestNoTokenConfigMeansNoAuth(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when no token configured, got %d", rec.Code)
	}
}

// TestStaticConsoleLoadsWithoutToken is the regression test for the lock-out
// bug: a tokened deployment must still serve the console shell (so an operator
// can reach the login), or the token would make the UI unreachable.
func TestStaticConsoleLoadsWithoutToken(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		rec := do(srv.Handler(), "GET", path, "")
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("static asset %s must load without a token, got 401", path)
		}
	}
}

// TestAuthAcceptsCookieToken proves browser-driven downloads/navigations, which
// cannot set an Authorization header, authenticate via the cookie.
func TestAuthAcceptsCookieToken(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.AddCookie(&http.Cookie{Name: "mirage_token", Value: "s3cret"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with a valid token cookie, got %d", rec.Code)
	}
	// A wrong cookie is still rejected.
	req2 := httptest.NewRequest("GET", "/api/stats", nil)
	req2.AddCookie(&http.Cookie{Name: "mirage_token", Value: "nope"})
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong token cookie must be rejected, got %d", rec2.Code)
	}
}

// --- Security headers ---

func TestSecurityHeaders(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/health", "")
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Fatal("missing CSP header")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing Referrer-Policy: no-referrer")
	}
}

// --- Endpoints ---

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/health", ""))
	if m["status"] != "ok" {
		t.Fatalf("health status: %v", m["status"])
	}
	if _, ok := m["uptime"]; !ok {
		t.Fatal("health missing uptime")
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/stats", ""))
	if m["tenant"] != "test-tenant" {
		t.Fatalf("tenant: %v", m["tenant"])
	}
	if m["site"] != "test-site" {
		t.Fatalf("site: %v", m["site"])
	}
	if _, ok := m["storage"]; !ok {
		t.Fatal("stats missing storage")
	}
}

func TestEventsEndpointEmpty(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/events", ""))
	evs, ok := m["events"].([]any)
	if !ok {
		t.Fatalf("events field not an array: %T", m["events"])
	}
	if len(evs) != 0 {
		t.Fatalf("expected 0 events, got %d", len(evs))
	}
}

func TestEventByUIDNotFound(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/events/nonexistent", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestEventByUIDFound(t *testing.T) {
	srv, st := newTestServer(t, "")
	e := event.New(event.ClassNetworkActivity, 1, event.SeverityMedium, event.PlaneHoneyd)
	st.events = append(st.events, e)

	rec := do(srv.Handler(), "GET", "/api/events/"+e.Metadata.UID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := doBody(srv.Handler(), "POST", "/api/evidence/verify", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	m := jsonBody(t, rec)
	if m["verified"] != true {
		t.Fatalf("expected verified=true, got %v", m["verified"])
	}
}

func TestSystemInfoEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/system", ""))
	if _, ok := m["go_version"]; !ok {
		t.Fatal("system info missing go_version")
	}
	if _, ok := m["os"]; !ok {
		t.Fatal("system info missing os")
	}
	if m["tenant"] != "test-tenant" {
		t.Fatalf("tenant: %v", m["tenant"])
	}
}

func TestEngagementsEmptyWithoutTracker(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/engagements", ""))
	engs, ok := m["engagements"].([]any)
	if !ok {
		t.Fatalf("engagements not an array: %T", m["engagements"])
	}
	if len(engs) != 0 {
		t.Fatalf("expected empty, got %d", len(engs))
	}
}

func TestTopologyAlwaysHasDirector(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/topology", ""))
	nodes, ok := m["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatal("topology should always include the director node")
	}
	first := nodes[0].(map[string]any)
	if first["id"] != "director" {
		t.Fatalf("first node should be director, got %v", first["id"])
	}
}

func TestObserverStatusWithoutDriver(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/observer", ""))
	if m["configured"] != false {
		t.Fatalf("expected configured=false without observer driver, got %v", m["configured"])
	}
}

func TestPresenceDisabledWithoutHub(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/presence", ""))
	if m["enabled"] != false {
		t.Fatalf("expected enabled=false without presence hub")
	}
}

func TestVMsDisabledWithoutProvisioner(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/vms", ""))
	if m["enabled"] != false {
		t.Fatalf("expected enabled=false without VM provisioner")
	}
}

func TestVMBurnWithoutProvisioner(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := doBody(srv.Handler(), "POST", "/api/vms/test/burn", "", `{"reason":"test"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without provisioner, got %d", rec.Code)
	}
}

func TestComplianceUnknownFramework(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/compliance/unknown", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown framework, got %d", rec.Code)
	}
}

func TestComplianceKnownFramework(t *testing.T) {
	srv, _ := newTestServer(t, "")
	for _, fw := range []string{"nis2", "dora", "iso27001", "pci", "soc2", "iec62443"} {
		rec := do(srv.Handler(), "GET", "/api/compliance/"+fw, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("/api/compliance/%s returned %d", fw, rec.Code)
		}
		m := jsonBody(t, rec)
		if _, ok := m["controls"]; !ok {
			t.Fatalf("/api/compliance/%s missing controls", fw)
		}
	}
}

func TestTokensEmptyWithoutStore(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/tokens", ""))
	toks, ok := m["tokens"].([]any)
	if !ok {
		t.Fatalf("tokens not an array: %T", m["tokens"])
	}
	if len(toks) != 0 {
		t.Fatalf("expected empty, got %d", len(toks))
	}
}

func TestDriversEmptyWithoutRegistry(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/drivers", ""))
	drivers, ok := m["drivers"].([]any)
	if !ok {
		t.Fatalf("drivers not an array: %T", m["drivers"])
	}
	if len(drivers) != 0 {
		t.Fatalf("expected empty, got %d", len(drivers))
	}
}

func TestGraphEndpointReturnsScaffold(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/graph", ""))
	if _, ok := m["message"]; !ok {
		t.Fatal("graph without estate should return a message")
	}
}

func TestEconomicsWithoutTracker(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/economics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestNewRequiresStore(t *testing.T) {
	_, err := New(":0", Deps{})
	if err == nil {
		t.Fatal("New should fail without a Store")
	}
}

func TestResponsesAreJSON(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/stats", "")
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
}

func TestHTMLEscapingInJSON(t *testing.T) {
	srv, st := newTestServer(t, "")
	e := event.New(event.ClassNetworkActivity, 1, event.SeverityMedium, event.PlaneHoneyd)
	e.Message = `<script>alert("xss")</script>`
	st.events = append(st.events, e)

	rec := do(srv.Handler(), "GET", "/api/events/"+e.Metadata.UID, "")
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("JSON response contains unescaped HTML: %s", body)
	}
}
