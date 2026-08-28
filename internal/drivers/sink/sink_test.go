package sink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

func sampleAlert() drivers.Alert {
	return drivers.Alert{
		ID:           "01ABCDEF",
		Time:         time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		Severity:     "critical",
		Title:        "Honeytoken accessed",
		Description:  "honeytoken read: /var/www/html/.env",
		SrcIP:        "198.51.100.7",
		DecoyID:      "dcy-web01",
		Service:      "ssh",
		EngagementID: "eng_abc",
		Techniques:   []string{"T1552.001"},
		URL:          "https://mirage.local/#/engagement/eng_abc",
		Fields: map[string]any{
			"username": "root", "honeytoken": "app-db-credential", "persona": "linux/web",
		},
	}
}

func TestECSMappingIsSchemaCorrect(t *testing.T) {
	doc := ToECS(sampleAlert())

	if _, ok := doc["@timestamp"].(string); !ok {
		t.Fatal("ECS requires @timestamp")
	}
	ev, ok := doc["event"].(map[string]any)
	if !ok {
		t.Fatal("no event object")
	}
	if ev["kind"] != "alert" {
		t.Errorf("event.kind = %v, want alert", ev["kind"])
	}
	if ev["severity"].(int) < 80 {
		t.Errorf("critical mapped to severity %v", ev["severity"])
	}
	src, ok := doc["source"].(map[string]any)
	if !ok || src["ip"] != "198.51.100.7" {
		t.Errorf("source.ip missing: %v", doc["source"])
	}
	// Identity dashboards join on user.name, so a username must reach it.
	user, ok := doc["user"].(map[string]any)
	if !ok || user["name"] != "root" {
		t.Errorf("user.name missing: %v", doc["user"])
	}
	threat, ok := doc["threat"].(map[string]any)
	if !ok {
		t.Fatal("no threat object for a mapped technique")
	}
	tech := threat["technique"].(map[string]any)
	if ids := tech["id"].([]string); len(ids) != 1 || ids[0] != "T1552.001" {
		t.Errorf("threat.technique.id = %v", tech["id"])
	}

	// MIRAGE context must be namespaced, not scattered at the top level where
	// it would collide with other producers' fields.
	mirage, ok := doc["mirage"].(map[string]any)
	if !ok {
		t.Fatal("no mirage object")
	}
	if mirage["honeytoken"] != "app-db-credential" {
		t.Errorf("mirage.honeytoken = %v", mirage["honeytoken"])
	}
	if _, collides := doc["honeytoken"]; collides {
		t.Error("MIRAGE fields leaked into the top level")
	}

	// The whole document must survive JSON encoding: a map that does not is a
	// runtime failure in the delivery path.
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("ECS document is not serialisable: %v", err)
	}
}

func TestElasticSendsBulkAndDetectsPerDocumentFailure(t *testing.T) {
	var gotPath, gotBody, gotAuth string
	failing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`{"version":{"number":"8.13.0"}}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		gotPath, gotBody, gotAuth = r.URL.Path, string(body), r.Header.Get("Authorization")
		if failing {
			// A bulk request can return 200 while the document is rejected.
			w.Write([]byte(`{"errors":true,"items":[{"create":{"status":400,"error":{"type":"mapper_parsing_exception"}}}]}`))
			return
		}
		w.Write([]byte(`{"errors":false,"items":[{"create":{"status":201}}]}`))
	}))
	defer srv.Close()

	d, err := NewElastic(map[string]any{
		"url": srv.URL, "index": "mirage-test", "username": "elastic", "password": "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := d.(*Elastic)
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := s.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("send: %v", err)
	}

	if gotPath != "/mirage-test/_bulk" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotBody, `{"create":{}}`) || strings.Count(gotBody, "\n") != 2 {
		t.Errorf("body is not valid ndjson:\n%s", gotBody)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("authorization = %q", gotAuth)
	}

	failing = true
	err = s.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("a rejected document must not be reported as delivered")
	}
	if !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Errorf("the error should carry Elasticsearch's reason: %v", err)
	}
}

func TestSplunkSendsHECEnvelope(t *testing.T) {
	var got map[string]any
	var auth string
	code := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		if code != 0 {
			w.Write([]byte(`{"text":"Incorrect index","code":7}`))
			return
		}
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	d, err := NewSplunk(map[string]any{
		"url": srv.URL, "token": "abc123", "index": "main", "sourcetype": "mirage:alert",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := d.(*Splunk)
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := s.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("send: %v", err)
	}

	if auth != "Splunk abc123" {
		t.Errorf("authorization = %q", auth)
	}
	if got["sourcetype"] != "mirage:alert" || got["index"] != "main" {
		t.Errorf("envelope = %v", got)
	}
	if _, ok := got["event"].(map[string]any)["@timestamp"]; !ok {
		t.Error("the event payload is not the ECS document")
	}

	// HEC answers 200 with a failure code in the body; treating that as
	// success would silently lose every alert.
	code = 7
	if err := s.Send(context.Background(), sampleAlert()); err == nil {
		t.Fatal("a HEC error code in a 200 response must be reported")
	}
}

func TestSinkConfigurationIsValidated(t *testing.T) {
	cases := []struct {
		name string
		new  func(map[string]any) (drivers.Driver, error)
		cfg  map[string]any
		want string
	}{
		{"elastic without url", NewElastic, map[string]any{}, "url is required"},
		{"splunk without url", NewSplunk, map[string]any{}, "url is required"},
		{"splunk without token", NewSplunk, map[string]any{"url": "https://x"}, "token is required"},
		{"webhook without url", NewWebhook, map[string]any{}, "url is required"},
		{"file without path", NewFile, map[string]any{}, "path is required"},
		{"syslog without address", NewSyslog, map[string]any{}, "address is required"},
		{"syslog bad network", NewSyslog, map[string]any{"address": "h:514", "network": "carrier-pigeon"}, "udp or tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.new(tc.cfg)
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
}
