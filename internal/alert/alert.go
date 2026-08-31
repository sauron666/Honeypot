// Package alert turns events into notifications and delivers them to sinks.
//
// The gate here is the product's promise: deception produces few alerts and
// every one of them is real. Forwarding routine telemetry would make MIRAGE
// just another source of noise in the SIEM.
package alert

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/assure"
	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

// Dispatcher fans alerts out to sinks.
type Dispatcher struct {
	mu    sync.RWMutex
	sinks []drivers.SinkDriver

	minSeverity event.Severity
	publicURL   string
	log         *slog.Logger

	// dedupe suppresses repeats of the same alert from the same source within
	// a window: a brute-force run must produce one alert, not four hundred.
	dedupeWindow time.Duration
	recent       map[string]time.Time

	sent, suppressed, failed uint64
}

// Options configures a Dispatcher.
type Options struct {
	MinSeverity  event.Severity
	PublicURL    string
	DedupeWindow time.Duration
	Log          *slog.Logger
}

// NewDispatcher builds a dispatcher.
func NewDispatcher(opts Options) *Dispatcher {
	if opts.MinSeverity == 0 {
		opts.MinSeverity = event.SeverityHigh
	}
	if opts.DedupeWindow == 0 {
		opts.DedupeWindow = 5 * time.Minute
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Dispatcher{
		minSeverity:  opts.MinSeverity,
		publicURL:    strings.TrimSuffix(opts.PublicURL, "/"),
		log:          opts.Log,
		dedupeWindow: opts.DedupeWindow,
		recent:       map[string]time.Time{},
	}
}

// AddSink registers a destination.
func (d *Dispatcher) AddSink(s drivers.SinkDriver) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sinks = append(d.sinks, s)
}

// SinkInfos returns each registered sink's driver info, in order. It is what the
// console lists; it carries no secrets (the Info summary is driver-authored and
// redacted), only which destinations are wired.
func (d *Dispatcher) SinkInfos() []drivers.Info {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]drivers.Info, 0, len(d.sinks))
	for _, s := range d.sinks {
		out = append(out, s.Info())
	}
	return out
}

// RemoveSinkAt drops the sink at index i (as listed by SinkInfos). It reports
// whether an index was in range. Removing a sink only stops future delivery;
// evidence already in the store is untouched.
func (d *Dispatcher) RemoveSinkAt(i int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || i >= len(d.sinks) {
		return false
	}
	d.sinks = append(d.sinks[:i], d.sinks[i+1:]...)
	return true
}

// MinSeverity reports the current alerting threshold.
func (d *Dispatcher) MinSeverity() event.Severity {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.minSeverity
}

// SetMinSeverity changes the threshold at runtime, so an operator can turn the
// alarm volume up during an incident or down when tuning, without a restart.
func (d *Dispatcher) SetMinSeverity(s event.Severity) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.minSeverity = s
}

// TestResult reports how one sink handled a test alert.
type TestResult struct {
	Sink  string `json:"sink"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SendTest delivers a clearly-marked synthetic alert to every sink, so an
// operator can confirm the wiring reaches their SIEM before relying on it in an
// incident. The alert is stamped synthetic so it is never mistaken for real.
func (d *Dispatcher) SendTest(ctx context.Context) []TestResult {
	d.mu.RLock()
	sinks := append([]drivers.SinkDriver(nil), d.sinks...)
	d.mu.RUnlock()

	a := drivers.Alert{
		ID:          "test-" + time.Now().UTC().Format("20060102T150405Z"),
		Time:        time.Now(),
		Severity:    event.SeverityHigh.String(),
		Title:       "MIRAGE test alert",
		Description: "Synthetic test alert from the operator console. If you can see this in your SIEM, alert delivery works. No intrusion occurred.",
		Fields:      map[string]any{"synthetic": true, "source": "console-test"},
	}
	out := make([]TestResult, 0, len(sinks))
	for _, s := range sinks {
		r := TestResult{Sink: s.Info().Name, OK: true}
		if err := s.Send(ctx, a); err != nil {
			r.OK = false
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// Handle considers one event for alerting. It is safe to wire directly to the
// bus; delivery happens inline, so sinks must be fast or buffered.
func (d *Dispatcher) Handle(ctx context.Context, e *event.Event) {
	if !d.shouldAlert(e) {
		return
	}
	key := dedupeKey(e)

	d.mu.Lock()
	if last, ok := d.recent[key]; ok && time.Since(last) < d.dedupeWindow {
		d.suppressed++
		d.mu.Unlock()
		return
	}
	d.recent[key] = time.Now()
	if len(d.recent) > 10000 {
		d.pruneLocked()
	}
	sinks := append([]drivers.SinkDriver(nil), d.sinks...)
	d.mu.Unlock()

	a := d.buildAlert(e)
	for _, s := range sinks {
		if err := s.Send(ctx, a); err != nil {
			d.mu.Lock()
			d.failed++
			d.mu.Unlock()
			// A failing sink must never take the platform down with it; the
			// evidence is already durable in the store.
			d.log.Error("alert delivery failed", "sink", s.Info().Name, "err", err, "alert_id", a.ID)
			continue
		}
		d.mu.Lock()
		d.sent++
		d.mu.Unlock()
	}
}

func (d *Dispatcher) shouldAlert(e *event.Event) bool {
	if e.SeverityID >= d.minSeverity {
		return true
	}
	// Some events are worth an alert regardless of severity, because they mean
	// the deception worked exactly as designed.
	switch e.ClassUID {
	case event.ClassTokenTriggered, event.ClassContainment:
		return true
	case event.ClassCredentialOffer:
		v, _ := e.Get("accepted")
		return v == true
	}
	return e.GetString("honeytoken") != ""
}

// dedupeKey groups repeats. Source, decoy, class and finding are enough: the
// second identical probe from the same host adds nothing an analyst needs.
func dedupeKey(e *event.Event) string {
	src := ""
	if e.Src != nil {
		src = e.Src.IP
	}
	return strings.Join([]string{
		src, e.Mirage.DecoyID, e.Mirage.Service, e.ClassUID.String(), e.GetString("honeytoken"),
	}, "|")
}

func (d *Dispatcher) pruneLocked() {
	cutoff := time.Now().Add(-d.dedupeWindow)
	for k, t := range d.recent {
		if t.Before(cutoff) {
			delete(d.recent, k)
		}
	}
}

func (d *Dispatcher) buildAlert(e *event.Event) drivers.Alert {
	// Synthetic traffic from the assurance runner must never be mistaken for a
	// real intrusion, in a queue, a metric or a report.
	synthetic := assure.IsSynthetic(e)

	a := drivers.Alert{
		ID:           e.Metadata.UID,
		Time:         e.Timestamp(),
		Severity:     e.SeverityID.String(),
		Title:        title(e),
		Description:  e.Message,
		DecoyID:      e.Mirage.DecoyID,
		Service:      e.Mirage.Service,
		EngagementID: e.Mirage.EngagementID,
		Fields:       map[string]any{},
	}
	if e.Src != nil {
		a.SrcIP = e.Src.IP
	}
	for _, t := range e.Mirage.Attack {
		if t.Technique != "" {
			a.Techniques = append(a.Techniques, t.Technique)
		}
	}
	// Every alert links back to its engagement: an analyst should never have to
	// go looking for the context.
	if d.publicURL != "" && e.Mirage.EngagementID != "" {
		a.URL = d.publicURL + "/#/engagement/" + e.Mirage.EngagementID
	}
	for _, k := range []string{"username", "command", "url", "honeytoken", "file_path",
		"http_method", "url_path", "client_tool", "payload_kind", "findings"} {
		if v, ok := e.Get(k); ok {
			a.Fields[k] = v
		}
	}
	a.Fields["persona"] = e.Mirage.Persona
	a.Fields["event_class"] = e.ClassUID.String()
	if synthetic {
		a.Fields["synthetic"] = true
		a.Title = "[self-test] " + a.Title
	}
	return a
}

func title(e *event.Event) string {
	switch e.ClassUID {
	case event.ClassCredentialOffer:
		if v, _ := e.Get("accepted"); v == true {
			return "Attacker authenticated to a decoy"
		}
		return "Credentials offered to a decoy"
	case event.ClassAuthentication:
		return "Decoy login succeeded"
	case event.ClassCommandExecuted:
		return "Command executed on a decoy"
	case event.ClassFileActivity:
		if e.GetString("honeytoken") != "" {
			return "Honeytoken accessed"
		}
		return "File accessed on a decoy"
	case event.ClassDetectionFinding:
		return "Attack technique observed on a decoy"
	case event.ClassContainment:
		return "Containment guard fired"
	case event.ClassEngagement:
		return "Engagement update"
	default:
		return "Decoy interaction"
	}
}

// Stats reports delivery counters.
func (d *Dispatcher) Stats() (sent, suppressed, failed uint64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sent, d.suppressed, d.failed
}
