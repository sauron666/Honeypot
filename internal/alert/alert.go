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
