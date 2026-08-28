package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// ElasticInfo describes the Elasticsearch sink.
func ElasticInfo() drivers.Info {
	return drivers.Info{
		Name: "elastic", Kind: drivers.KindSink,
		Summary: "Indexes alerts into Elasticsearch or OpenSearch as ECS documents, " +
			"so they land in the same schema as the rest of the estate's telemetry.",
		Capabilities: []drivers.Capability{drivers.CapAlert, drivers.CapBulk},
	}
}

// Elastic writes alerts to Elasticsearch or OpenSearch.
//
// The documents are mapped to ECS rather than shipped raw. An alert that does
// not match the schema an analyst's dashboards and correlation rules already
// use is an alert they will not see.
type Elastic struct {
	url    string
	index  string
	auth   string
	client *http.Client
}

// NewElastic builds the sink. Config keys: "url" (required, e.g.
// https://es:9200), "index" (default mirage-alerts), "username"/"password" or
// "api_key", "insecure_skip_verify", "timeout_seconds".
func NewElastic(cfg map[string]any) (drivers.Driver, error) {
	url, _ := cfg["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("sink/elastic: url is required")
	}
	index, _ := cfg["index"].(string)
	if index == "" {
		index = "mirage-alerts"
	}

	auth := ""
	if key, _ := cfg["api_key"].(string); key != "" {
		auth = "ApiKey " + key
	} else if user, _ := cfg["username"].(string); user != "" {
		pass, _ := cfg["password"].(string)
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	timeout := 15 * time.Second
	if v, ok := cfg["timeout_seconds"].(int); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}
	tr := &http.Transport{}
	if skip, _ := cfg["insecure_skip_verify"].(bool); skip {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Elastic{
		url: strings.TrimSuffix(url, "/"), index: index, auth: auth,
		client: &http.Client{Timeout: timeout, Transport: tr},
	}, nil
}

func (e *Elastic) Info() drivers.Info { return ElasticInfo() }

func (e *Elastic) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url+"/", nil)
	if err != nil {
		return err
	}
	if e.auth != "" {
		req.Header.Set("Authorization", e.auth)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/elastic: %s unreachable: %w", e.url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("sink/elastic: %s returned %s", e.url, resp.Status)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("sink/elastic: %s rejected the credentials", e.url)
	}
	return nil
}

func (e *Elastic) Close() error { return nil }

func (e *Elastic) Send(ctx context.Context, a drivers.Alert) error {
	doc, err := json.Marshal(ToECS(a))
	if err != nil {
		return err
	}
	// The bulk API is used even for one document: it is the endpoint that
	// works identically on Elasticsearch and OpenSearch across versions.
	var body bytes.Buffer
	body.WriteString(`{"create":{}}` + "\n")
	body.Write(doc)
	body.WriteString("\n")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.url+"/"+e.index+"/_bulk", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if e.auth != "" {
		req.Header.Set("Authorization", e.auth)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/elastic: bulk: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sink/elastic: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	// A bulk request can return 200 while individual documents fail, which
	// would otherwise look like success and lose the alert.
	var result struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int             `json:"status"`
			Error  json.RawMessage `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &result); err == nil && result.Errors {
		for _, item := range result.Items {
			for _, v := range item {
				if v.Status >= 300 {
					return fmt.Errorf("sink/elastic: document rejected (%d): %s", v.Status, v.Error)
				}
			}
		}
		return fmt.Errorf("sink/elastic: the bulk request reported errors")
	}
	return nil
}

var _ drivers.SinkDriver = (*Elastic)(nil)

// ToECS maps an alert onto the Elastic Common Schema.
//
// The mapping is deliberate: event.kind "alert", a threat.technique block that
// dashboards can pivot on, and the MIRAGE-specific context under a namespaced
// object rather than scattered at the top level where it would collide with
// other producers.
func ToECS(a drivers.Alert) map[string]any {
	doc := map[string]any{
		"@timestamp": a.Time.UTC().Format(time.RFC3339Nano),
		"message":    a.Description,
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{"info"},
			"severity": ecsSeverity(a.Severity),
			"module":   "mirage",
			"dataset":  "mirage.deception",
			"provider": "MIRAGE",
			"id":       a.ID,
			"url":      a.URL,
		},
		"rule": map[string]any{
			"name":        a.Title,
			"description": a.Description,
		},
		"observer": map[string]any{
			"type":   "deception",
			"vendor": "MIRAGE",
			"name":   a.DecoyID,
		},
		"tags": []string{"mirage", "deception"},
	}
	if a.SrcIP != "" {
		doc["source"] = map[string]any{"ip": a.SrcIP}
		doc["related"] = map[string]any{"ip": []string{a.SrcIP}}
	}
	if a.Service != "" {
		doc["network"] = map[string]any{"protocol": a.Service}
	}
	if len(a.Techniques) > 0 {
		doc["threat"] = map[string]any{
			"framework": "MITRE ATT&CK",
			"technique": map[string]any{"id": a.Techniques},
		}
	}

	// MIRAGE context lives under its own key: flattening it would collide with
	// fields other producers own.
	mirage := map[string]any{
		"decoy_id":      a.DecoyID,
		"service":       a.Service,
		"engagement_id": a.EngagementID,
	}
	for k, v := range a.Fields {
		mirage[k] = v
	}
	doc["mirage"] = mirage

	// A user name belongs in the ECS user object as well, because that is what
	// identity dashboards join on.
	if u, ok := a.Fields["username"].(string); ok && u != "" {
		doc["user"] = map[string]any{"name": u}
	}
	return doc
}

// ecsSeverity maps our names to the numeric scale ECS expects.
func ecsSeverity(name string) int {
	switch strings.ToLower(name) {
	case "fatal":
		return 99
	case "critical":
		return 90
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 1
	}
}
