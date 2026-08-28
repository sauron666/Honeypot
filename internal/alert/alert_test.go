package alert

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/drivers"
	"github.com/sauron666/Honeypot/internal/event"
)

type fakeSink struct {
	mu     sync.Mutex
	got    []drivers.Alert
	failAt int
	calls  int
}

func (f *fakeSink) Info() drivers.Info {
	return drivers.Info{Name: "fake", Kind: drivers.KindSink}
}
func (f *fakeSink) Probe(context.Context) error { return nil }
func (f *fakeSink) Close() error                { return nil }

func (f *fakeSink) Send(_ context.Context, a drivers.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failAt > 0 && f.calls == f.failAt {
		return errors.New("sink is down")
	}
	f.got = append(f.got, a)
	return nil
}

func (f *fakeSink) alerts() []drivers.Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]drivers.Alert(nil), f.got...)
}

func mkEvent(class event.Class, sev event.Severity, src string) *event.Event {
	e := event.New(class, 1, sev, event.PlaneHoneyd)
	e.Mirage.DecoyID = "dcy_web"
	e.Mirage.Service = "ssh"
	e.Mirage.EngagementID = "eng_abc"
	e.WithSrc(src, 4444).WithMessage("test event")
	return e
}

func newDispatcher(t *testing.T, min event.Severity) (*Dispatcher, *fakeSink) {
	t.Helper()
	d := NewDispatcher(Options{
		MinSeverity: min, PublicURL: "https://mirage.local",
		DedupeWindow: time.Minute, Log: slog.New(slog.DiscardHandler),
	})
	s := &fakeSink{}
	d.AddSink(s)
	return d, s
}

func TestLowSeverityIsNotForwarded(t *testing.T) {
	d, s := newDispatcher(t, event.SeverityHigh)
	d.Handle(context.Background(), mkEvent(event.ClassHTTPActivity, event.SeverityLow, "198.51.100.1"))
	if len(s.alerts()) != 0 {
		t.Fatal("routine telemetry must not reach a sink")
	}
	d.Handle(context.Background(), mkEvent(event.ClassDetectionFinding, event.SeverityCritical, "198.51.100.1"))
	if len(s.alerts()) != 1 {
		t.Fatal("critical findings must be forwarded")
	}
}

func TestAcceptedCredentialAlwaysAlerts(t *testing.T) {
	// Even configured to be quiet, an attacker getting in is always worth
	// waking someone for.
	d, s := newDispatcher(t, event.SeverityFatal)
	e := mkEvent(event.ClassCredentialOffer, event.SeverityLow, "198.51.100.2")
	e.Set("accepted", true).Set("username", "root")
	d.Handle(context.Background(), e)

	got := s.alerts()
	if len(got) != 1 {
		t.Fatal("an accepted credential must always alert")
	}
	if got[0].Title != "Attacker authenticated to a decoy" {
		t.Fatalf("title = %q", got[0].Title)
	}
	if got[0].Fields["username"] != "root" {
		t.Fatalf("username missing from alert: %+v", got[0].Fields)
	}
}

func TestHoneytokenAlwaysAlerts(t *testing.T) {
	d, s := newDispatcher(t, event.SeverityFatal)
	e := mkEvent(event.ClassFileActivity, event.SeverityLow, "198.51.100.3")
	e.Set("honeytoken", "app-db-credential")
	d.Handle(context.Background(), e)
	if len(s.alerts()) != 1 {
		t.Fatal("a honeytoken read must always alert")
	}
}

func TestDedupeCollapsesBruteForce(t *testing.T) {
	d, s := newDispatcher(t, event.SeverityHigh)
	for i := 0; i < 50; i++ {
		d.Handle(context.Background(), mkEvent(event.ClassCredentialOffer, event.SeverityHigh, "198.51.100.4"))
	}
	if n := len(s.alerts()); n != 1 {
		t.Fatalf("brute force produced %d alerts, want 1", n)
	}
	// A different source is a different alert.
	d.Handle(context.Background(), mkEvent(event.ClassCredentialOffer, event.SeverityHigh, "198.51.100.5"))
	if n := len(s.alerts()); n != 2 {
		t.Fatalf("second source produced %d alerts, want 2", n)
	}
	_, suppressed, _ := d.Stats()
	if suppressed != 49 {
		t.Fatalf("suppressed = %d, want 49", suppressed)
	}
}

func TestAlertCarriesEngagementLink(t *testing.T) {
	d, s := newDispatcher(t, event.SeverityHigh)
	e := mkEvent(event.ClassDetectionFinding, event.SeverityCritical, "198.51.100.6")
	e.WithAttack(event.Technique{Technique: "T1105"})
	d.Handle(context.Background(), e)

	got := s.alerts()[0]
	if got.URL != "https://mirage.local/#/engagement/eng_abc" {
		t.Fatalf("alert link = %q", got.URL)
	}
	if len(got.Techniques) != 1 || got.Techniques[0] != "T1105" {
		t.Fatalf("techniques = %v", got.Techniques)
	}
}

func TestFailingSinkDoesNotStopOthers(t *testing.T) {
	d, first := newDispatcher(t, event.SeverityHigh)
	first.failAt = 1
	second := &fakeSink{}
	d.AddSink(second)

	d.Handle(context.Background(), mkEvent(event.ClassDetectionFinding, event.SeverityCritical, "198.51.100.7"))

	if len(second.alerts()) != 1 {
		t.Fatal("a failing sink must not prevent delivery to the others")
	}
	if _, _, failed := d.Stats(); failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
}

func TestSyntheticProbesAreMarkedInAlerts(t *testing.T) {
	// Self-test traffic must never be mistaken for an intrusion in a queue,
	// a metric or a report.
	d, s := newDispatcher(t, event.SeverityHigh)
	e := mkEvent(event.ClassCredentialOffer, event.SeverityHigh, "127.0.0.1")
	e.Set("username", "MIRAGE-ASSURE-abc123")
	d.Handle(context.Background(), e)

	got := s.alerts()
	if len(got) != 1 {
		t.Fatalf("got %d alerts", len(got))
	}
	if got[0].Fields["synthetic"] != true {
		t.Fatalf("the alert is not marked synthetic: %+v", got[0].Fields)
	}
	if !strings.HasPrefix(got[0].Title, "[self-test]") {
		t.Fatalf("title should say it is a self-test: %q", got[0].Title)
	}
}
