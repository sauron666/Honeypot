package assure

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/store"
)

// blindStore records nothing, which is exactly the failure the self-test
// exists to catch: the decoy answers, and the evidence goes nowhere.
type blindStore struct {
	mu     sync.Mutex
	events []*event.Event
}

func (b *blindStore) add(e *event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e)
}

func (b *blindStore) Append(context.Context, *event.Event) error { return nil }
func (b *blindStore) Get(context.Context, string) (*event.Event, error) {
	return nil, store.ErrNotFound
}
func (b *blindStore) Head() (uint64, string)       { return 0, "" }
func (b *blindStore) Verify(context.Context) error { return nil }
func (b *blindStore) Stats() store.Stats           { return store.Stats{} }
func (b *blindStore) Close() error                 { return nil }

func (b *blindStore) Query(_ context.Context, q store.Query) ([]*event.Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*event.Event
	for _, e := range b.events {
		if q.Matches(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// echoListener accepts connections and speaks just enough to let a scenario
// complete, standing in for a decoy.
func echoListener(t *testing.T, script func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				script(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestScenarioIsSkippedWhenTheServiceIsNotDeployed(t *testing.T) {
	r := &Runner{Targets: map[string]string{}, Store: &blindStore{}, Timeout: time.Second}
	rep := r.Run(context.Background(), DefaultScenarios())

	if rep.SkippedN != len(DefaultScenarios()) {
		t.Fatalf("skipped %d of %d scenarios", rep.SkippedN, len(DefaultScenarios()))
	}
	if rep.Healthy {
		t.Fatal("a deployment where nothing was tested must not report healthy")
	}
	if !strings.Contains(rep.Summary, "nothing was tested") {
		t.Fatalf("summary should say nothing ran: %q", rep.Summary)
	}
	for _, res := range rep.Results {
		if res.Reason == "" {
			t.Errorf("scenario %s was skipped without a reason", res.Scenario)
		}
	}
}

func TestUnreachableDecoyIsReportedAsSuch(t *testing.T) {
	// Point at a port nothing is listening on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()

	r := &Runner{
		Targets: map[string]string{"http": dead},
		Store:   &blindStore{}, Timeout: 500 * time.Millisecond,
	}
	rep := r.Run(context.Background(), DefaultScenarios()[:1])

	if len(rep.Results) != 1 {
		t.Fatalf("got %d results", len(rep.Results))
	}
	res := rep.Results[0]
	if res.Acted {
		t.Fatal("a scenario against a dead listener must not report that it acted")
	}
	if res.Error == "" {
		t.Fatal("the failure was not explained")
	}
	if rep.Healthy {
		t.Fatal("a dead decoy must fail the self-test")
	}
}

func TestDecoyAnswersButEvidenceNeverArrives(t *testing.T) {
	// The most dangerous failure mode: everything looks alive from outside,
	// and nothing is being recorded.
	addr := echoListener(t, func(c net.Conn) {
		c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	})
	r := &Runner{
		Targets: map[string]string{"http": addr},
		Store:   &blindStore{}, Timeout: 700 * time.Millisecond,
	}
	rep := r.Run(context.Background(), DefaultScenarios()[:1])

	res := rep.Results[0]
	if !res.Acted {
		t.Fatal("the probe should have completed against a live listener")
	}
	if res.Recorded {
		t.Fatal("nothing was stored, so the probe must not report evidence")
	}
	if !strings.Contains(res.Error, "no evidence") {
		t.Fatalf("the error should name the missing evidence, got %q", res.Error)
	}
	if rep.Healthy || rep.Failed != 1 {
		t.Fatalf("report should show one failure: %+v", rep)
	}
	// The operator needs to know what this failure costs them.
	if res.Why == "" {
		t.Fatal("a failing scenario must explain what breaks silently")
	}
}

func TestEvidenceFromAnotherProbeDoesNotCount(t *testing.T) {
	addr := echoListener(t, func(c net.Conn) {
		c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	})
	st := &blindStore{}
	r := &Runner{Targets: map[string]string{"http": addr}, Store: st, Timeout: 3 * time.Second}

	// Record evidence as soon as the probe is expected to have run.
	go func() {
		time.Sleep(200 * time.Millisecond)
		e := event.New(event.ClassHTTPActivity, 1, event.SeverityLow, event.PlaneHoneyd)
		e.WithMessage("GET /.env").Set("user_agent", Marker+"/anything")
		st.add(e)
	}()

	// The nonce is unique per run, so a generic marker event will not satisfy
	// the check -- which is the point. Verify the shape of the failure instead.
	rep := r.Run(context.Background(), DefaultScenarios()[:1])
	if rep.Results[0].Recorded {
		t.Fatal("evidence from a different probe must not satisfy this one")
	}
}

func TestIsSyntheticRecognisesProbes(t *testing.T) {
	probe := event.New(event.ClassHTTPActivity, 1, event.SeverityLow, event.PlaneHoneyd)
	probe.Set("user_agent", Marker+"/abc123")
	if !IsSynthetic(probe) {
		t.Fatal("a probe event was not recognised as synthetic")
	}

	inMessage := event.New(event.ClassDecoyInteraction, 1, event.SeverityLow, event.PlaneHoneyd)
	inMessage.WithMessage("credentials offered: %s-x", Marker)
	if !IsSynthetic(inMessage) {
		t.Fatal("the marker in the message was missed")
	}

	real := event.New(event.ClassHTTPActivity, 1, event.SeverityHigh, event.PlaneHoneyd)
	real.Set("user_agent", "sqlmap/1.7").Set("command", "cat /etc/shadow")
	if IsSynthetic(real) {
		t.Fatal("a real intrusion was misread as a self-test")
	}
}
