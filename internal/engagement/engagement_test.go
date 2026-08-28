package engagement

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

type sink struct {
	mu sync.Mutex
	ev []*event.Event
}

func (s *sink) emit(_ context.Context, e *event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ev)
}

func ev(class event.Class, srcIP, engID, decoy, service string, sev event.Severity) *event.Event {
	e := event.New(class, 1, sev, event.PlaneHoneyd)
	e.Mirage.EngagementID = engID
	e.Mirage.DecoyID = decoy
	e.Mirage.Service = service
	e.Mirage.TenantID, e.Mirage.SiteID = "t", "s"
	e.WithSrc(srcIP, 1234)
	return e
}

func TestSameSourceSharesOneEngagement(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: time.Hour})

	a := tr.Resolve("198.51.100.7", "dcy_web", "ssh")
	b := tr.Resolve("198.51.100.7", "dcy_db", "http")
	c := tr.Resolve("203.0.113.9", "dcy_web", "ssh")

	if a != b {
		t.Fatal("one source touching two decoys must be one engagement")
	}
	if a == c {
		t.Fatal("different sources must not share an engagement")
	}
	eng, ok := tr.Get(a)
	if !ok {
		t.Fatal("engagement not found")
	}
	if len(eng.Decoys) != 2 || len(eng.Services) != 2 {
		t.Fatalf("engagement should span both decoys and services: %+v", eng)
	}
}

func TestIdleTimeoutStartsANewEngagement(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: 10 * time.Minute})
	now := time.Now()
	tr.now = func() time.Time { return now }

	first := tr.Resolve("198.51.100.7", "d", "ssh")
	now = now.Add(11 * time.Minute)
	second := tr.Resolve("198.51.100.7", "d", "ssh")

	if first == second {
		t.Fatal("a visit after the idle window must be a new engagement")
	}
	old, _ := tr.Get(first)
	if old.Active {
		t.Fatal("the previous engagement must be closed")
	}
}

func TestObserveBuildsTheStory(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: time.Hour})
	id := tr.Resolve("198.51.100.7", "dcy_web", "ssh")

	cred := ev(event.ClassCredentialOffer, "198.51.100.7", id, "dcy_web", "ssh", event.SeverityHigh)
	cred.Set("accepted", true)
	tr.Observe(cred)

	cmd := ev(event.ClassCommandExecuted, "198.51.100.7", id, "dcy_web", "ssh", event.SeverityMedium)
	cmd.WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1082"})
	tr.Observe(cmd)

	tok := ev(event.ClassFileActivity, "198.51.100.7", id, "dcy_web", "ssh", event.SeverityCritical)
	tok.Set("honeytoken", "app-db-credential")
	tr.Observe(tok)

	eng, _ := tr.Get(id)
	if !eng.Authenticated {
		t.Error("accepted credential must mark the engagement authenticated")
	}
	if eng.Commands != 1 || eng.Credentials != 1 {
		t.Errorf("counters wrong: %+v", eng)
	}
	if len(eng.HoneytokensHit) != 1 {
		t.Error("honeytoken hit not recorded")
	}
	if eng.MaxSeverity != event.SeverityCritical {
		t.Errorf("max severity = %s", eng.MaxSeverity)
	}
	// The summary is what an analyst triages from, so it must name the worst
	// thing that happened, not the most recent.
	if eng.Summary != "attacker read planted credentials after authenticating to a decoy" {
		t.Errorf("summary = %q", eng.Summary)
	}
	if eng.RiskScore < 50 {
		t.Errorf("risk score = %d; an authenticated session that read bait should rank high", eng.RiskScore)
	}
}

func TestRiskScoreOrdersTriage(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: time.Hour})

	quiet := tr.Resolve("198.51.100.1", "d", "http")
	tr.Observe(ev(event.ClassHTTPActivity, "198.51.100.1", quiet, "d", "http", event.SeverityLow))

	loud := tr.Resolve("198.51.100.2", "d", "ssh")
	c := ev(event.ClassCredentialOffer, "198.51.100.2", loud, "d", "ssh", event.SeverityHigh)
	c.Set("accepted", true)
	tr.Observe(c)
	for i := 0; i < 6; i++ {
		tr.Observe(ev(event.ClassCommandExecuted, "198.51.100.2", loud, "d", "ssh", event.SeverityMedium))
	}
	f := ev(event.ClassDetectionFinding, "198.51.100.2", loud, "d", "ssh", event.SeverityCritical)
	f.Set("url", "http://198.51.100.66/x.sh")
	tr.Observe(f)

	ranked := tr.Active()
	if len(ranked) != 2 {
		t.Fatalf("got %d engagements", len(ranked))
	}
	if ranked[0].ID != loud {
		t.Fatalf("triage order is wrong: %d (%s) before %d (%s)",
			ranked[0].RiskScore, ranked[0].ID, ranked[1].RiskScore, ranked[1].ID)
	}
	if len(ranked[0].PayloadURLs) != 1 {
		t.Error("payload URL not carried on the engagement")
	}
}

func TestObserveIgnoresForeignEvents(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: time.Hour})
	id := tr.Resolve("198.51.100.7", "d", "ssh")

	// An event carrying a stale engagement id must not corrupt live state.
	stale := ev(event.ClassCommandExecuted, "198.51.100.7", "eng_bogus", "d", "ssh", event.SeverityHigh)
	tr.Observe(stale)
	// So must an event with no engagement at all.
	tr.Observe(ev(event.ClassCommandExecuted, "198.51.100.7", "", "d", "ssh", event.SeverityHigh))

	eng, _ := tr.Get(id)
	if eng.Commands != 0 || eng.Events != 0 {
		t.Fatalf("foreign events leaked into the engagement: %+v", eng)
	}
}

func TestSweepClosesQuietEngagements(t *testing.T) {
	s := &sink{}
	tr := NewTracker(Options{IdleTimeout: 5 * time.Minute, Emit: s.emit})
	now := time.Now()
	tr.now = func() time.Time { return now }

	tr.Resolve("198.51.100.7", "d", "ssh")
	tr.Resolve("198.51.100.8", "d", "ssh")
	if n := tr.Sweep(); n != 0 {
		t.Fatalf("swept %d fresh engagements", n)
	}

	now = now.Add(10 * time.Minute)
	if n := tr.Sweep(); n != 2 {
		t.Fatalf("swept %d, want 2", n)
	}
	active, closed := tr.Stats()
	if active != 0 || closed != 2 {
		t.Fatalf("active=%d closed=%d", active, closed)
	}
	// Opening and closing are both lifecycle events an operator can alert on.
	if s.count() != 4 {
		t.Fatalf("emitted %d lifecycle events, want 4 (2 open + 2 close)", s.count())
	}
}

func TestConcurrentResolveAndObserve(t *testing.T) {
	tr := NewTracker(Options{IdleTimeout: time.Hour})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "198.51.100.7"
			id := tr.Resolve(ip, "d", "ssh")
			for j := 0; j < 20; j++ {
				tr.Observe(ev(event.ClassCommandExecuted, ip, id, "d", "ssh", event.SeverityLow))
			}
		}(i)
	}
	wg.Wait()

	act := tr.Active()
	if len(act) != 1 {
		t.Fatalf("concurrent contact from one source produced %d engagements", len(act))
	}
	if act[0].Commands != 400 {
		t.Fatalf("commands = %d, want 400", act[0].Commands)
	}
}

func TestFromEventsRebuildsTheSameStoryAsTheLiveTracker(t *testing.T) {
	// An analyst opening last month's incident from the evidence file must see
	// exactly what the live console showed at the time.
	tr := NewTracker(Options{IdleTimeout: time.Hour})
	id := tr.Resolve("198.51.100.7", "dcy-web01", "ssh")

	var recorded []*event.Event
	record := func(e *event.Event) {
		recorded = append(recorded, e)
		tr.Observe(e)
	}

	cred := ev(event.ClassCredentialOffer, "198.51.100.7", id, "dcy-web01", "ssh", event.SeverityHigh)
	cred.Set("accepted", true)
	record(cred)

	for i := 0; i < 4; i++ {
		c := ev(event.ClassCommandExecuted, "198.51.100.7", id, "dcy-web01", "ssh", event.SeverityMedium)
		c.WithAttack(event.Technique{Tactic: "TA0007", Technique: "T1082"})
		record(c)
	}
	tok := ev(event.ClassFileActivity, "198.51.100.7", id, "dcy-web01", "ssh", event.SeverityCritical)
	tok.Set("honeytoken", "app-db-credential")
	record(tok)

	find := ev(event.ClassDetectionFinding, "198.51.100.7", id, "dcy-db01", "redis", event.SeverityCritical)
	find.Set("url", "http://198.51.100.66/x.sh")
	record(find)

	live, _ := tr.Get(id)
	replayed := FromEvents(recorded)
	if len(replayed) != 1 {
		t.Fatalf("replay produced %d engagements", len(replayed))
	}
	r := replayed[0]

	if r.ID != live.ID || r.SrcIP != live.SrcIP {
		t.Fatalf("identity differs: %s/%s vs %s/%s", r.ID, r.SrcIP, live.ID, live.SrcIP)
	}
	if r.Events != live.Events || r.Commands != live.Commands || r.Credentials != live.Credentials {
		t.Fatalf("counters differ: replay %+v vs live %+v", r, live)
	}
	if r.Authenticated != live.Authenticated || r.RiskScore != live.RiskScore {
		t.Fatalf("risk differs: replay %d/%v vs live %d/%v",
			r.RiskScore, r.Authenticated, live.RiskScore, live.Authenticated)
	}
	if r.Summary != live.Summary {
		t.Fatalf("summary differs:\n replay: %s\n live:   %s", r.Summary, live.Summary)
	}
	if len(r.Techniques) != len(live.Techniques) || len(r.Decoys) != len(live.Decoys) {
		t.Fatalf("techniques/decoys differ: %v/%v vs %v/%v",
			r.Techniques, r.Decoys, live.Techniques, live.Decoys)
	}
	if len(r.HoneytokensHit) != 1 || len(r.PayloadURLs) != 1 {
		t.Fatalf("replay lost artifacts: %+v", r)
	}
}

func TestFromEventsIgnoresEventsWithoutAnEngagement(t *testing.T) {
	orphan := event.New(event.ClassDecoyInteraction, 1, event.SeverityLow, event.PlaneHoneyd)
	if got := FromEvents([]*event.Event{orphan}); len(got) != 0 {
		t.Fatalf("got %d engagements from an orphan event", len(got))
	}
}
