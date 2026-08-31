package analyst

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/engagement"
	"github.com/sauron666/Honeypot/internal/event"
)

// populated is a representative closed engagement: authenticated, hands-on,
// with a honeytoken read and techniques mapped. Both analysts are exercised
// against it.
func populated() engagement.Engagement {
	return engagement.Engagement{
		ID:              "eng-test-01",
		SrcIP:           "203.0.113.7",
		StartedAt:       time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC),
		LastSeen:        time.Date(2026, 8, 31, 10, 42, 0, 0, time.UTC),
		Decoys:          []string{"dcy-web01", "dcy-db01"},
		Services:        []string{"ssh", "mysql"},
		Techniques:      []string{"T1110", "T1078"},
		Events:          37,
		Credentials:     5,
		Authenticated:   true,
		Commands:        9,
		HoneytokensHit:  []string{"aws-key-canary"},
		PayloadURLs:     []string{"http://evil.example/x.sh"},
		RiskScore:       88,
		MaxSeverity:     event.SeverityCritical,
		AttackerSummary: "42 minutes",
	}
}

func TestTemplateProducesNarrative(t *testing.T) {
	n, err := Template{}.Analyze(context.Background(), populated())
	if err != nil {
		t.Fatalf("template must never error: %v", err)
	}
	if n.Summary == "" || n.ReportDraft == "" || n.SuggestedSigma == "" {
		t.Fatalf("expected non-empty fields, got %+v", n)
	}
	if !n.RequiresReview {
		t.Error("RequiresReview must always be true")
	}
	if n.Source != "template" {
		t.Errorf("Source = %q, want template", n.Source)
	}
	// Real synthesis from the data: the source, id and technique should surface.
	if !strings.Contains(n.ReportDraft, "203.0.113.7") {
		t.Error("report should mention the source IP")
	}
	if !strings.Contains(n.SuggestedSigma, "attack.t1110") {
		t.Errorf("sigma should carry the mapped technique tag, got:\n%s", n.SuggestedSigma)
	}
	if !strings.Contains(n.SuggestedSigma, "203.0.113.7") {
		t.Error("sigma selection should carry the source IP")
	}
}

func TestTemplateIsDeterministic(t *testing.T) {
	eng := populated()
	a, _ := Template{}.Analyze(context.Background(), eng)
	b, _ := Template{}.Analyze(context.Background(), eng)
	if a != b {
		t.Error("template output must be identical for identical input")
	}
}

func TestTemplateHandlesEmptyEngagement(t *testing.T) {
	// The air-gap fallback must never error, even on a bare engagement.
	n, err := Template{}.Analyze(context.Background(), engagement.Engagement{ID: "eng-empty"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Summary == "" || n.ReportDraft == "" || n.SuggestedSigma == "" {
		t.Error("even an empty engagement must produce a full narrative")
	}
	if !n.RequiresReview {
		t.Error("RequiresReview must always be true")
	}
}

// fakeChatServer stands in for a local OpenAI-compatible server. It records the
// last request path and decoded body so the test can assert on what was sent.
func fakeChatServer(t *testing.T, content string) (*httptest.Server, *struct {
	Path  string
	Model string
	Auth  string
}) {
	t.Helper()
	seen := &struct {
		Path  string
		Model string
		Auth  string
	}{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		seen.Path = r.URL.Path
		seen.Auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		_ = json.Unmarshal(body, &req)
		seen.Model = req.Model
		resp := chatResponse{}
		resp.Choices = append(resp.Choices, struct {
			Message chatMessage `json:"message"`
		}{Message: chatMessage{Role: "assistant", Content: content}})
		json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux), seen
}

func TestLLMAnalyze(t *testing.T) {
	const answer = "Confirmed hands-on intrusion from 203.0.113.7.\n\nThe actor authenticated and read a honeytoken."
	srv, seen := fakeChatServer(t, answer)
	defer srv.Close()

	l := NewLLM(srv.URL+"/v1", "llama3.1", "secret-key")
	n, err := l.Analyze(context.Background(), populated())
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if seen.Path != "/v1/chat/completions" {
		t.Errorf("request path = %q, want /v1/chat/completions", seen.Path)
	}
	if seen.Model != "llama3.1" {
		t.Errorf("model = %q, want llama3.1", seen.Model)
	}
	if seen.Auth != "Bearer secret-key" {
		t.Errorf("auth header = %q, want Bearer secret-key", seen.Auth)
	}
	if n.ReportDraft != answer {
		t.Errorf("ReportDraft = %q, want the returned content", n.ReportDraft)
	}
	if n.Summary != "Confirmed hands-on intrusion from 203.0.113.7." {
		t.Errorf("Summary = %q, want the first line", n.Summary)
	}
	if !n.RequiresReview {
		t.Error("RequiresReview must be true")
	}
	if n.Source != "llm:llama3.1" {
		t.Errorf("Source = %q, want llm:llama3.1", n.Source)
	}
}

func TestLLMNoAuthHeaderWhenKeyEmpty(t *testing.T) {
	srv, seen := fakeChatServer(t, "A summary line.\n\nBody.")
	defer srv.Close()

	l := NewLLM(srv.URL+"/v1", "llama3.1", "")
	if _, err := l.Analyze(context.Background(), populated()); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if seen.Auth != "" {
		t.Errorf("no Authorization header expected when APIKey is empty, got %q", seen.Auth)
	}
}

func TestLLMServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	l := NewLLM(srv.URL+"/v1", "llama3.1", "")
	if _, err := l.Analyze(context.Background(), populated()); err == nil {
		t.Error("a 500 response must return an error, not succeed")
	}
}

func TestLLMUnreachableReturnsError(t *testing.T) {
	// Nothing is listening here; Analyze must return an error, not panic.
	l := NewLLM("http://127.0.0.1:1/v1", "llama3.1", "")
	if _, err := l.Analyze(context.Background(), populated()); err == nil {
		t.Error("an unreachable endpoint must return an error")
	}
}
