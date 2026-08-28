package bus

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

func testEvent() *event.Event {
	e := event.New(event.ClassDecoyInteraction, 1, event.SeverityMedium, event.PlaneHoneyd)
	e.Mirage.TenantID = "t"
	e.Mirage.SiteID = "s"
	e.Mirage.Service = "ssh"
	return e
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"mirage.events.>", "mirage.events.honeyd.ssh_activity", true},
		{"mirage.events.>", "mirage.events", false},
		{"mirage.events.*", "mirage.events.honeyd", true},
		{"mirage.events.*", "mirage.events.honeyd.ssh_activity", false},
		{"mirage.events.honeyd.*", "mirage.events.honeyd.ssh_activity", true},
		{"mirage.events.tap.>", "mirage.events.honeyd.ssh_activity", false},
		{"mirage.alerts", "mirage.alerts", true},
		{"mirage.alerts", "mirage.alertsX", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.subject); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}

func TestPublishDeliversToMatchingSubscribers(t *testing.T) {
	b := NewMemory(16, slog.Default())
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	var mu sync.Mutex
	got := map[string]int{}

	collect := func(name string) Handler {
		return func(_ context.Context, e *event.Event) {
			mu.Lock()
			got[name]++
			mu.Unlock()
			wg.Done()
		}
	}
	if _, err := b.Subscribe("mirage.events.>", collect("all")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Subscribe("mirage.events.honeyd.*", collect("honeyd")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Subscribe("mirage.events.tap.*", func(context.Context, *event.Event) {
		t.Error("tap subscriber must not receive a honeyd event")
	}); err != nil {
		t.Fatal(err)
	}

	if err := b.Publish(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	waitOrFail(t, &wg, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	if got["all"] != 1 || got["honeyd"] != 1 {
		t.Fatalf("delivery = %v, want one each", got)
	}
}

func TestSubscribersGetIndependentCopies(t *testing.T) {
	b := NewMemory(16, slog.Default())
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	var mu sync.Mutex
	seen := []*event.Event{}

	h := func(_ context.Context, e *event.Event) {
		mu.Lock()
		seen = append(seen, e)
		mu.Unlock()
		wg.Done()
	}
	b.Subscribe("mirage.events.>", h)
	b.Subscribe("mirage.events.honeyd.>", h)

	orig := testEvent()
	orig.Set("k", "v")
	b.Publish(context.Background(), orig)
	waitOrFail(t, &wg, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("got %d deliveries, want 2", len(seen))
	}
	seen[0].Set("k", "mutated")
	if seen[1].GetString("k") != "v" {
		t.Fatal("subscribers share the same event object")
	}
	if orig.GetString("k") != "v" {
		t.Fatal("subscriber mutation leaked back into the published event")
	}
}

func TestPublishRejectsInvalidEvent(t *testing.T) {
	b := NewMemory(4, slog.Default())
	defer b.Close()

	if err := b.Publish(context.Background(), nil); err != ErrNilEvent {
		t.Fatalf("nil event: got %v", err)
	}
	bad := testEvent()
	bad.Mirage.Plane = ""
	if err := b.Publish(context.Background(), bad); err != ErrInvalidEvent {
		t.Fatalf("invalid event: got %v, want ErrInvalidEvent", err)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	b := NewMemory(16, slog.Default())
	defer b.Close()

	var mu sync.Mutex
	n := 0
	sub, err := b.Subscribe("mirage.events.>", func(context.Context, *event.Event) {
		mu.Lock()
		n++
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	sub.Unsubscribe()
	sub.Unsubscribe() // must be idempotent

	b.Publish(context.Background(), testEvent())
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if n != 0 {
		t.Fatalf("received %d events after unsubscribe", n)
	}
}

func TestSlowSubscriberDoesNotBlockPublisher(t *testing.T) {
	b := NewMemory(2, slog.New(slog.DiscardHandler))
	defer b.Close()

	release := make(chan struct{})
	b.Subscribe("mirage.events.>", func(context.Context, *event.Event) {
		<-release
	})

	// A decoy handler must never be held up by a wedged consumer: publishing
	// far past the queue depth has to return promptly.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			b.Publish(context.Background(), testEvent())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked on a slow subscriber")
	}
	close(release)

	if _, dropped := b.Stats(); dropped == 0 {
		t.Fatal("overflow must be counted, not silently absorbed")
	}
}

func TestClosedBusRejectsPublish(t *testing.T) {
	b := NewMemory(4, slog.Default())
	b.Close()
	if err := b.Publish(context.Background(), testEvent()); err != ErrClosed {
		t.Fatalf("got %v, want ErrClosed", err)
	}
	if _, err := b.Subscribe("x.>", func(context.Context, *event.Event) {}); err != ErrClosed {
		t.Fatalf("subscribe after close: got %v", err)
	}
}

func waitOrFail(t *testing.T, wg *sync.WaitGroup, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("timed out waiting for deliveries")
	}
}

func TestCloseWaitsForInFlightHandlers(t *testing.T) {
	// Close must not return while handlers are still running: callers shut
	// down storage right afterwards, and a handler still writing to it is a
	// corrupt file or a lost event.
	b := NewMemory(64, slog.New(slog.DiscardHandler))

	var (
		mu        sync.Mutex
		completed int
		started   = make(chan struct{}, 1)
	)
	b.Subscribe("mirage.events.>", func(context.Context, *event.Event) {
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		completed++
		mu.Unlock()
	})

	for i := 0; i < 5; i++ {
		if err := b.Publish(context.Background(), testEvent()); err != nil {
			t.Fatal(err)
		}
	}
	<-started // make sure at least one handler is mid-flight

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if completed != 5 {
		t.Fatalf("Close returned with %d of 5 handlers finished", completed)
	}
}
