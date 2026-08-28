// Package sink holds SinkDriver implementations: how alerts leave MIRAGE.
// Sinks carry alerts, never raw telemetry -- drowning a customer's SIEM in
// syscall traces is how deception products get switched off.
package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
)

// ---------------------------------------------------------------------------
// stdout
// ---------------------------------------------------------------------------

// StdoutInfo describes the console sink.
func StdoutInfo() drivers.Info {
	return drivers.Info{
		Name: "stdout", Kind: drivers.KindSink,
		Summary:      "Writes alerts as JSON lines to stdout. Always available; the default for profile P0.",
		Capabilities: []drivers.Capability{drivers.CapAlert},
	}
}

// Stdout prints alerts as JSON lines.
type Stdout struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdout builds the console sink.
func NewStdout(map[string]any) (drivers.Driver, error) {
	return &Stdout{w: os.Stdout}, nil
}

func (s *Stdout) Info() drivers.Info          { return StdoutInfo() }
func (s *Stdout) Probe(context.Context) error { return nil }
func (s *Stdout) Close() error                { return nil }

func (s *Stdout) Send(_ context.Context, a drivers.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = fmt.Fprintf(s.w, "%s\n", b)
	return err
}

var _ drivers.SinkDriver = (*Stdout)(nil)

// ---------------------------------------------------------------------------
// webhook
// ---------------------------------------------------------------------------

// WebhookInfo describes the HTTP sink.
func WebhookInfo() drivers.Info {
	return drivers.Info{
		Name: "webhook", Kind: drivers.KindSink,
		Summary:      "POSTs alerts as JSON to a URL. Works with SOAR, chat bridges and anything else that speaks HTTP.",
		Capabilities: []drivers.Capability{drivers.CapAlert, drivers.CapBulk},
	}
}

// Webhook POSTs alerts to an HTTP endpoint.
type Webhook struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhook builds the HTTP sink. Config keys: "url" (required), "headers",
// "timeout_seconds", "insecure_skip_verify".
func NewWebhook(cfg map[string]any) (drivers.Driver, error) {
	url, _ := cfg["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("sink/webhook: url is required")
	}
	timeout := 10 * time.Second
	if v, ok := cfg["timeout_seconds"].(int); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}
	tr := &http.Transport{}
	if skip, _ := cfg["insecure_skip_verify"].(bool); skip {
		// Allowed for lab endpoints with self-signed certs, but never silently:
		// the operator has to ask for it in configuration.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	headers := map[string]string{}
	if raw, ok := cfg["headers"].(map[string]any); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}
	return &Webhook{url: url, headers: headers, client: &http.Client{Timeout: timeout, Transport: tr}}, nil
}

func (w *Webhook) Info() drivers.Info { return WebhookInfo() }

func (w *Webhook) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, w.url, nil)
	if err != nil {
		return err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/webhook: %s unreachable: %w", w.url, err)
	}
	resp.Body.Close()
	return nil
}

func (w *Webhook) Close() error { return nil }

func (w *Webhook) Send(ctx context.Context, a drivers.Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("sink/webhook: post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 {
		return fmt.Errorf("sink/webhook: %s returned %s", w.url, resp.Status)
	}
	return nil
}

var _ drivers.SinkDriver = (*Webhook)(nil)

// ---------------------------------------------------------------------------
// syslog
// ---------------------------------------------------------------------------

// SyslogInfo describes the syslog sink.
func SyslogInfo() drivers.Info {
	return drivers.Info{
		Name: "syslog", Kind: drivers.KindSink,
		Summary:      "RFC 5424 syslog over UDP or TCP, with the alert as structured JSON. The lowest common denominator every SIEM accepts.",
		Capabilities: []drivers.Capability{drivers.CapAlert},
	}
}

// Syslog sends RFC 5424 messages. It dials per message rather than holding a
// connection: alert volume is low by design, and a dead socket that silently
// swallows alerts is worse than a reconnect.
type Syslog struct {
	network  string
	address  string
	facility int
	hostname string
	timeout  time.Duration
}

// NewSyslog builds the syslog sink. Config keys: "address" (required, host:port),
// "network" (udp|tcp, default udp), "facility" (default 13, log audit).
func NewSyslog(cfg map[string]any) (drivers.Driver, error) {
	addr, _ := cfg["address"].(string)
	if addr == "" {
		return nil, fmt.Errorf("sink/syslog: address is required (host:port)")
	}
	network, _ := cfg["network"].(string)
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" {
		return nil, fmt.Errorf("sink/syslog: network must be udp or tcp, got %q", network)
	}
	facility := 13
	if v, ok := cfg["facility"].(int); ok {
		facility = v
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "mirage"
	}
	return &Syslog{network: network, address: addr, facility: facility, hostname: host, timeout: 5 * time.Second}, nil
}

func (s *Syslog) Info() drivers.Info { return SyslogInfo() }

func (s *Syslog) Probe(ctx context.Context) error {
	d := net.Dialer{Timeout: s.timeout}
	c, err := d.DialContext(ctx, s.network, s.address)
	if err != nil {
		return fmt.Errorf("sink/syslog: cannot reach %s/%s: %w", s.network, s.address, err)
	}
	return c.Close()
}

func (s *Syslog) Close() error { return nil }

// severityToSyslog maps our severities onto syslog severities.
func severityToSyslog(sev string) int {
	switch strings.ToLower(sev) {
	case "fatal", "critical":
		return 2 // critical
	case "high":
		return 3 // error
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	default:
		return 6 // informational
	}
}

func (s *Syslog) Send(ctx context.Context, a drivers.Alert) error {
	payload, err := json.Marshal(a)
	if err != nil {
		return err
	}
	pri := s.facility*8 + severityToSyslog(a.Severity)
	msg := fmt.Sprintf("<%d>1 %s %s mirage - %s - %s\n",
		pri, a.Time.UTC().Format(time.RFC3339), s.hostname, a.ID, payload)

	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, s.network, s.address)
	if err != nil {
		return fmt.Errorf("sink/syslog: dial: %w", err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return fmt.Errorf("sink/syslog: write: %w", err)
	}
	return nil
}

var _ drivers.SinkDriver = (*Syslog)(nil)

// ---------------------------------------------------------------------------
// file
// ---------------------------------------------------------------------------

// FileInfo describes the file sink.
func FileInfo() drivers.Info {
	return drivers.Info{
		Name: "file", Kind: drivers.KindSink,
		Summary:      "Appends alerts as JSON lines to a file, for log shippers (filebeat, promtail, rsyslog) to pick up.",
		Capabilities: []drivers.Capability{drivers.CapAlert},
	}
}

// File appends alerts to a JSON-lines file.
type File struct {
	mu   sync.Mutex
	path string
	f    *os.File
	log  *slog.Logger
}

// NewFile builds the file sink. Config key: "path" (required).
func NewFile(cfg map[string]any) (drivers.Driver, error) {
	path, _ := cfg["path"].(string)
	if path == "" {
		return nil, fmt.Errorf("sink/file: path is required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("sink/file: open %s: %w", path, err)
	}
	return &File{path: path, f: f, log: slog.Default()}, nil
}

func (f *File) Info() drivers.Info          { return FileInfo() }
func (f *File) Probe(context.Context) error { return nil }

func (f *File) Send(_ context.Context, a drivers.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.f.Sync()
}

func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.f == nil {
		return nil
	}
	err := f.f.Close()
	f.f = nil
	return err
}

var _ drivers.SinkDriver = (*File)(nil)
