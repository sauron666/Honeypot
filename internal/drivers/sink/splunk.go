package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// SplunkInfo describes the Splunk HEC sink.
func SplunkInfo() drivers.Info {
	return drivers.Info{
		Name: "splunk", Kind: drivers.KindSink,
		Summary: "Sends alerts to a Splunk HTTP Event Collector, with the sourcetype " +
			"and index the deployment expects.",
		Capabilities: []drivers.Capability{drivers.CapAlert, drivers.CapBulk},
	}
}

// Splunk delivers alerts through the HTTP Event Collector.
type Splunk struct {
	url        string
	token      string
	index      string
	sourcetype string
	host       string
	client     *http.Client
}

// NewSplunk builds the sink. Config keys: "url" (required, e.g.
// https://splunk:8088), "token" (required), "index", "sourcetype", "host",
// "insecure_skip_verify", "timeout_seconds".
func NewSplunk(cfg map[string]any) (drivers.Driver, error) {
	url, _ := cfg["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("sink/splunk: url is required")
	}
	token, _ := cfg["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("sink/splunk: token is required (HEC token)")
	}
	get := func(key, def string) string {
		if v, ok := cfg[key].(string); ok && v != "" {
			return v
		}
		return def
	}
	timeout := 15 * time.Second
	if v, ok := cfg["timeout_seconds"].(int); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}
	tr := &http.Transport{}
	if skip, _ := cfg["insecure_skip_verify"].(bool); skip {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Splunk{
		url:        strings.TrimSuffix(url, "/"),
		token:      token,
		index:      get("index", ""),
		sourcetype: get("sourcetype", "mirage:alert"),
		host:       get("host", "mirage"),
		client:     &http.Client{Timeout: timeout, Transport: tr},
	}, nil
}

func (s *Splunk) Info() drivers.Info { return SplunkInfo() }

func (s *Splunk) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.url+"/services/collector/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/splunk: %s unreachable: %w", s.url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sink/splunk: health check returned %s", resp.Status)
	}
	return nil
}

func (s *Splunk) Close() error { return nil }

func (s *Splunk) Send(ctx context.Context, a drivers.Alert) error {
	envelope := map[string]any{
		"time":       float64(a.Time.UnixNano()) / 1e9,
		"host":       s.host,
		"source":     "mirage",
		"sourcetype": s.sourcetype,
		"event":      ToECS(a),
	}
	if s.index != "" {
		envelope["index"] = s.index
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.url+"/services/collector/event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/splunk: post: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sink/splunk: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	// HEC answers 200 with a body describing the failure for things like a bad
	// index, so the status code alone is not enough.
	var result struct {
		Text string `json:"text"`
		Code int    `json:"code"`
	}
	if err := json.Unmarshal(raw, &result); err == nil && result.Code != 0 {
		return fmt.Errorf("sink/splunk: HEC rejected the event: %s (code %d)", result.Text, result.Code)
	}
	return nil
}

var _ drivers.SinkDriver = (*Splunk)(nil)
