package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPacksEndpointListsBuiltins(t *testing.T) {
	srv, _ := newTestServer(t, "")
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/packs", ""))
	list, ok := m["packs"].([]any)
	if !ok || len(list) < 2 {
		t.Fatalf("expected built-in packs, got %v", m["packs"])
	}
}

func TestPackDetailEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rec := do(srv.Handler(), "GET", "/api/packs/finance-en", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a known pack, got %d", rec.Code)
	}
	if do(srv.Handler(), "GET", "/api/packs/nope", "").Code != http.StatusNotFound {
		t.Fatal("unknown pack should be 404")
	}
}

func TestSaasidAndWirelessAndBecEndpoints(t *testing.T) {
	srv, _ := newTestServer(t, "")
	if do(srv.Handler(), "GET", "/api/saasid?domain=acme.com", "").Code != http.StatusOK {
		t.Fatal("saasid endpoint failed")
	}
	if do(srv.Handler(), "GET", "/api/wireless", "").Code != http.StatusOK {
		t.Fatal("wireless endpoint failed")
	}
	if do(srv.Handler(), "GET", "/api/bec?domain=acme.com", "").Code != http.StatusOK {
		t.Fatal("bec kit endpoint failed")
	}
}

func TestBecAnalyzeEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "")
	raw := "From: \"CFO\" <cfo@acme.com>\r\nReply-To: evil@x.example\r\nSubject: wire\r\n\r\nbody\r\n"
	req := httptest.NewRequest("POST", "/api/bec/analyze", strings.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze endpoint returned %d", rec.Code)
	}
	m := jsonBody(t, rec)
	if m["is_bec"] != true {
		t.Fatalf("a spoofed-reply mail should be flagged BEC, got %v", m["is_bec"])
	}
}
