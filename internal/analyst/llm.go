package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/engagement"
)

// LLM is an optional analyst backed by a local, OpenAI-compatible chat server
// (ollama, llama.cpp, LM Studio, vLLM). It is offline by intent: the endpoint
// is meant to be something like http://localhost:11434/v1, self-hosted, so no
// engagement data leaves the operator's network.
//
// It is never load-bearing. On any error -- unreachable server, HTTP failure,
// unparseable body -- Analyze returns the error and the caller falls back to
// Template. It never panics and it is never on the alerting path.
type LLM struct {
	Endpoint string // base URL, e.g. http://localhost:11434/v1
	Model    string // model name the server exposes, e.g. "llama3.1"
	APIKey   string // optional; sent as a bearer token only when non-empty
	HTTP     *http.Client
}

// NewLLM builds an LLM analyst. A nil HTTP client is filled in at request time
// with a 60s timeout -- a local model can be slow, but a hung request must not
// pin a goroutine forever.
func NewLLM(endpoint, model, apiKey string) *LLM {
	return &LLM{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Model:    model,
		APIKey:   apiKey,
	}
}

// chat request/response shapes for the OpenAI-compatible /chat/completions API.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Analyze asks the local model for an incident summary and returns it as a
// Narrative. The Sigma suggestion is still produced by the deterministic
// template: an LLM-authored detection rule is exactly the kind of confidently
// wrong output that must not reach a SIEM unchecked, whereas a summary is prose
// a human will read anyway.
func (l *LLM) Analyze(ctx context.Context, eng engagement.Engagement) (Narrative, error) {
	reqBody := chatRequest{
		Model: l.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt(eng)},
		},
		Stream: false,
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return Narrative{}, fmt.Errorf("analyst: marshal request: %w", err)
	}

	url := l.Endpoint + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return Narrative{}, fmt.Errorf("analyst: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if l.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.APIKey)
	}

	client := l.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return Narrative{}, fmt.Errorf("analyst: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Narrative{}, fmt.Errorf("analyst: server returned HTTP %d", resp.StatusCode)
	}

	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return Narrative{}, fmt.Errorf("analyst: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Narrative{}, fmt.Errorf("analyst: response had no choices")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return Narrative{}, fmt.Errorf("analyst: response content was empty")
	}

	return Narrative{
		Summary:        firstParagraph(content),
		ReportDraft:    content,
		SuggestedSigma: templateSigma(eng),
		RequiresReview: true,
		Source:         "llm:" + l.Model,
	}, nil
}

// firstParagraph pulls a one-line summary out of the model's answer: the first
// non-empty line, which the prompt asks the model to make a standalone summary.
func firstParagraph(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return s
}

const systemPrompt = "You are an offline security analyst assistant. You write concise, " +
	"factual incident summaries from honeypot (deception) engagement data. Stay strictly " +
	"inside the facts you are given; do not invent indicators, attribution, or intent. " +
	"Begin your answer with a single-sentence summary on its own line, then a short " +
	"incident narrative. Your output is a draft that a human analyst will review."

// userPrompt turns the engagement into the model's input. It mirrors the fields
// the template uses so the two analysts see the same evidence.
func userPrompt(eng engagement.Engagement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Engagement ID: %s\n", eng.ID)
	fmt.Fprintf(&b, "Source IP: %s\n", orNA(eng.SrcIP))
	fmt.Fprintf(&b, "First seen: %s\n", eng.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Last seen: %s\n", eng.LastSeen.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Decoys touched: %s\n", listOrNone(eng.Decoys))
	fmt.Fprintf(&b, "Services probed: %s\n", listOrNone(eng.Services))
	fmt.Fprintf(&b, "ATT&CK techniques: %s\n", listOrNone(eng.Techniques))
	fmt.Fprintf(&b, "Events: %d (peak severity %s)\n", eng.Events, eng.MaxSeverity)
	fmt.Fprintf(&b, "Credentials offered: %d\n", eng.Credentials)
	fmt.Fprintf(&b, "Authenticated: %s\n", yesNo(eng.Authenticated))
	fmt.Fprintf(&b, "Commands executed: %d\n", eng.Commands)
	fmt.Fprintf(&b, "Honeytokens read: %s\n", listOrNone(eng.HoneytokensHit))
	fmt.Fprintf(&b, "Payload URLs: %s\n", listOrNone(eng.PayloadURLs))
	fmt.Fprintf(&b, "Risk score: %d/100\n", eng.RiskScore)
	b.WriteString("\nWrite the incident summary and narrative.")
	return b.String()
}
