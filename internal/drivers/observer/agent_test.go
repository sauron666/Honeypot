package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	d, err := NewAgent(map[string]any{"listen": "127.0.0.1:0", "token": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	a := d.(*Agent)
	t.Cleanup(func() { a.Close() })
	return a
}

func postSightings(t *testing.T, a *Agent, token string, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+a.Addr()+"/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestAgentIsNotAgentless(t *testing.T) {
	// The whole point: honest about the in-guest footprint.
	for _, c := range AgentInfo().Capabilities {
		if c == drivers.CapAgentless {
			t.Fatal("the agent observer must NOT claim CapAgentless")
		}
	}
}

func TestAgentRequiresToken(t *testing.T) {
	if _, err := NewAgent(map[string]any{"listen": "127.0.0.1:0"}); err == nil {
		t.Fatal("expected an error when no token is configured")
	}
}

func TestAgentRejectsBadToken(t *testing.T) {
	a := newTestAgent(t)
	code := postSightings(t, a, "wrong", []byte(`{"decoy_id":"d1","kind":"process","action":"exec"}`))
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad token, got %d", code)
	}
}

func TestAgentStreamsSightingsToObserver(t *testing.T) {
	a := newTestAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := a.Observe(ctx, "web01")
	if err != nil {
		t.Fatal(err)
	}

	s := drivers.Sighting{
		DecoyID: "web01", Kind: "process", Action: "exec",
		Process: "bash", CommandLine: "sudo su -", User: "www-data",
	}
	body, _ := json.Marshal(s)
	if code := postSightings(t, a, "s3cret", body); code != 200 {
		t.Fatalf("ingest returned %d", code)
	}

	select {
	case got := <-ch:
		if got.CommandLine != "sudo su -" || got.DecoyID != "web01" {
			t.Fatalf("wrong sighting delivered: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sighting delivered to the observer stream")
	}
}

func TestAgentAcceptsNDJSONAndArray(t *testing.T) {
	a := newTestAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := a.Observe(ctx, "db01")

	ndjson := []byte(`{"decoy_id":"db01","kind":"process","action":"exec","command_line":"id"}` + "\n" +
		`{"decoy_id":"db01","kind":"file","action":"write","target":"/etc/passwd"}`)
	if code := postSightings(t, a, "s3cret", ndjson); code != 200 {
		t.Fatalf("ingest returned %d", code)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("missing sighting %d", i)
		}
	}
}

func TestAgentDropsWhenNoSubscriber(t *testing.T) {
	a := newTestAgent(t)
	// No Observe for this decoy: the event is accepted-but-dropped, not an error.
	body := []byte(`{"decoy_id":"ghost","kind":"process","action":"exec"}`)
	if code := postSightings(t, a, "s3cret", body); code != 200 {
		t.Fatalf("ingest returned %d", code)
	}
}
