// Package engagement stitches individual events into the story of one
// attacker's visit.
//
// An intrusion is not a list of alerts. It is one actor moving between decoys
// and services over time, and the analyst needs it presented that way: one
// object, one timeline, one report. Everything MIRAGE emits carries the
// engagement id assigned here.
package engagement

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
	"github.com/sauron666/Honeypot/internal/version"
)

// Phase is where in the kill chain an engagement has reached.
type Phase string

const (
	PhaseRecon    Phase = "reconnaissance"
	PhaseAccess   Phase = "initial-access"
	PhaseDiscover Phase = "discovery"
	PhaseCredent  Phase = "credential-access"
	PhaseLateral  Phase = "lateral-movement"
	PhaseImpact   Phase = "impact"
)

// Engagement is one attacker's interaction with the deception fabric.
type Engagement struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id"`
	SrcIP    string `json:"src_ip"`

	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Active    bool      `json:"active"`

	Decoys     []string `json:"decoys"`
	Services   []string `json:"services"`
	Techniques []string `json:"techniques"`
	Phases     []Phase  `json:"phases"`

	Events         int            `json:"events"`
	MaxSeverity    event.Severity `json:"max_severity"`
	Credentials    int            `json:"credentials_offered"`
	Authenticated  bool           `json:"authenticated"`
	Commands       int            `json:"commands"`
	HoneytokensHit []string       `json:"honeytokens_hit,omitempty"`
	PayloadURLs    []string       `json:"payload_urls,omitempty"`
	// RiskScore is 0-100. It exists so that a queue of engagements can be
	// ordered by "look at this one first" rather than by time.
	RiskScore int `json:"risk_score"`

	// Summary is a one-line description an analyst can triage from.
	Summary string `json:"summary"`
}

// Tracker maintains live engagements.
type Tracker struct {
	mu     sync.Mutex
	active map[string]*Engagement // keyed by source IP
	closed []*Engagement

	idleTimeout time.Duration
	maxClosed   int
	emit        func(context.Context, *event.Event)
	now         func() time.Time
}

// Options configures a Tracker.
type Options struct {
	// IdleTimeout is how long a source can be silent before its engagement is
	// considered finished. Too short and one intrusion becomes ten reports;
	// too long and unrelated visits merge.
	IdleTimeout time.Duration
	MaxClosed   int
	Emit        func(context.Context, *event.Event)
}

// NewTracker builds a tracker.
func NewTracker(opts Options) *Tracker {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.MaxClosed <= 0 {
		opts.MaxClosed = 5000
	}
	return &Tracker{
		active:      map[string]*Engagement{},
		idleTimeout: opts.IdleTimeout,
		maxClosed:   opts.MaxClosed,
		emit:        opts.Emit,
		now:         time.Now,
	}
}

// Resolve implements honeyd.EngagementResolver: it returns the engagement id
// for a source, opening a new engagement if this is first contact.
func (t *Tracker) Resolve(srcIP, decoyID, service string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	e, ok := t.active[srcIP]
	if ok && now.Sub(e.LastSeen) > t.idleTimeout {
		t.closeLocked(e, now)
		ok = false
	}
	if !ok {
		e = &Engagement{
			ID: event.ShortID("eng"), SrcIP: srcIP,
			StartedAt: now, LastSeen: now, Active: true,
			Phases: []Phase{PhaseRecon},
		}
		t.active[srcIP] = e
		t.emitLifecycle(e, "engagement opened", event.SeverityMedium)
	}
	e.LastSeen = now
	addUnique(&e.Decoys, decoyID)
	addUnique(&e.Services, service)
	return e.ID
}

// Observe folds an event into its engagement. It is the single place where an
// engagement's state changes, so the summary and score cannot drift from the
// evidence.
func (t *Tracker) Observe(e *event.Event) {
	if e.Mirage.EngagementID == "" || e.Src == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	eng, ok := t.active[e.Src.IP]
	if !ok || eng.ID != e.Mirage.EngagementID {
		return
	}

	eng.LastSeen = t.now()
	eng.TenantID, eng.SiteID = e.Mirage.TenantID, e.Mirage.SiteID
	applyEvent(eng, e)

	eng.RiskScore = score(eng)
	eng.Summary = summarize(eng)
}

// Sweep closes engagements that have gone quiet. Call it periodically.
func (t *Tracker) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	n := 0
	for ip, e := range t.active {
		if now.Sub(e.LastSeen) > t.idleTimeout {
			t.closeLocked(e, now)
			delete(t.active, ip)
			n++
		}
	}
	return n
}

func (t *Tracker) closeLocked(e *Engagement, now time.Time) {
	e.Active = false
	e.EndedAt = now
	e.Summary = summarize(e)
	delete(t.active, e.SrcIP)
	t.closed = append(t.closed, e)
	if len(t.closed) > t.maxClosed {
		t.closed = t.closed[len(t.closed)-t.maxClosed:]
	}
	t.emitLifecycle(e, "engagement closed", severityFor(e))
}

func (t *Tracker) emitLifecycle(e *Engagement, msg string, sev event.Severity) {
	if t.emit == nil {
		return
	}
	ev := event.New(event.ClassEngagement, 1, sev, event.PlaneDirector)
	ev.Metadata.Product = event.Product{
		Name: version.Product, VendorName: version.Vendor, Version: version.Version, Feature: "engagement",
	}
	ev.Mirage.TenantID, ev.Mirage.SiteID = e.TenantID, e.SiteID
	ev.Mirage.EngagementID = e.ID
	ev.WithSrc(e.SrcIP, 0).WithMessage("%s: %s", msg, summarize(e))
	ev.Set("engagement_id", e.ID).
		Set("events", e.Events).
		Set("risk_score", e.RiskScore).
		Set("decoys", e.Decoys).
		Set("services", e.Services).
		Set("techniques", e.Techniques).
		Set("authenticated", e.Authenticated)
	t.emit(context.Background(), ev)
}

func severityFor(e *Engagement) event.Severity {
	switch {
	case e.RiskScore >= 80:
		return event.SeverityCritical
	case e.RiskScore >= 50:
		return event.SeverityHigh
	case e.RiskScore >= 25:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

// score ranks an engagement 0-100. The weights encode what actually matters:
// getting in beats knocking, and touching bait beats getting in.
func score(e *Engagement) int {
	s := 5 // any contact with a decoy is already abnormal
	if e.Credentials > 0 {
		s += 15
	}
	if e.Authenticated {
		s += 25
	}
	s += min(e.Commands*2, 20)
	s += min(len(e.Techniques)*3, 15)
	s += min(len(e.Decoys)*4, 12)
	s += len(e.HoneytokensHit) * 10
	s += len(e.PayloadURLs) * 8
	if e.MaxSeverity >= event.SeverityCritical {
		s += 15
	}
	if s > 100 {
		s = 100
	}
	return s
}

func summarize(e *Engagement) string {
	switch {
	case len(e.HoneytokensHit) > 0:
		return "attacker read planted credentials after authenticating to a decoy"
	case len(e.PayloadURLs) > 0:
		return "attacker attempted to stage a remote payload on a decoy"
	case e.Authenticated && e.Commands > 0:
		return "hands-on-keyboard session on a decoy"
	case e.Authenticated:
		return "authenticated to a decoy"
	case e.Credentials > 3:
		return "credential brute force against a decoy"
	case e.Credentials > 0:
		return "credential attempt against a decoy"
	case len(e.Services) > 2:
		return "multi-service probing of a decoy"
	default:
		return "contact with a decoy"
	}
}

// Active returns live engagements, highest risk first.
func (t *Tracker) Active() []*Engagement {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Engagement, 0, len(t.active))
	for _, e := range t.active {
		cp := *e
		out = append(out, &cp)
	}
	sortByRisk(out)
	return out
}

// Recent returns the most recent engagements, active ones first.
func (t *Tracker) Recent(limit int) []*Engagement {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Engagement, 0, len(t.active)+len(t.closed))
	for _, e := range t.active {
		cp := *e
		out = append(out, &cp)
	}
	for i := len(t.closed) - 1; i >= 0 && len(out) < limit+len(t.active); i-- {
		cp := *t.closed[i]
		out = append(out, &cp)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns one engagement by id.
func (t *Tracker) Get(id string) (*Engagement, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.active {
		if e.ID == id {
			cp := *e
			return &cp, true
		}
	}
	for _, e := range t.closed {
		if e.ID == id {
			cp := *e
			return &cp, true
		}
	}
	return nil, false
}

// Stats summarises tracker state.
func (t *Tracker) Stats() (active, closed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active), len(t.closed)
}

func sortByRisk(in []*Engagement) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].RiskScore != in[j].RiskScore {
			return in[i].RiskScore > in[j].RiskScore
		}
		return in[i].LastSeen.After(in[j].LastSeen)
	})
}

func addUnique(list *[]string, v string) {
	if v == "" {
		return
	}
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

func addPhase(e *Engagement, p Phase) {
	for _, x := range e.Phases {
		if x == p {
			return
		}
	}
	e.Phases = append(e.Phases, p)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FromEvents reconstructs engagements from stored events.
//
// The live tracker is not available when working from an evidence file -- an
// analyst opening last month's incident, or `miragectl forge` running offline
// -- so the same state machine is replayed over the record instead. This is why
// every event carries its engagement id: the story can always be rebuilt.
func FromEvents(events []*event.Event) []*Engagement {
	byID := map[string]*Engagement{}
	var order []string

	for _, e := range events {
		id := e.Mirage.EngagementID
		if id == "" {
			continue
		}
		eng, ok := byID[id]
		if !ok {
			eng = &Engagement{
				ID: id, TenantID: e.Mirage.TenantID, SiteID: e.Mirage.SiteID,
				StartedAt: e.Timestamp(), LastSeen: e.Timestamp(),
				Phases: []Phase{PhaseRecon},
			}
			if e.Src != nil {
				eng.SrcIP = e.Src.IP
			}
			byID[id] = eng
			order = append(order, id)
		}
		if t := e.Timestamp(); t.Before(eng.StartedAt) {
			eng.StartedAt = t
		} else if t.After(eng.LastSeen) {
			eng.LastSeen = t
		}
		applyEvent(eng, e)
	}

	out := make([]*Engagement, 0, len(order))
	for _, id := range order {
		eng := byID[id]
		eng.EndedAt = eng.LastSeen
		eng.RiskScore = score(eng)
		eng.Summary = summarize(eng)
		out = append(out, eng)
	}
	sortByRisk(out)
	return out
}

// applyEvent folds one event into an engagement. Observe and FromEvents share
// it so that a replayed engagement is identical to the live one.
func applyEvent(eng *Engagement, e *event.Event) {
	eng.Events++
	if e.SeverityID > eng.MaxSeverity {
		eng.MaxSeverity = e.SeverityID
	}
	addUnique(&eng.Decoys, e.Mirage.DecoyID)
	addUnique(&eng.Services, e.Mirage.Service)
	for _, tech := range e.Mirage.Attack {
		if tech.Technique != "" {
			addUnique(&eng.Techniques, tech.Technique)
		}
		switch tech.Tactic {
		case "TA0008":
			addPhase(eng, PhaseLateral)
		case "TA0040", "TA0105", "TA0106":
			addPhase(eng, PhaseImpact)
		}
	}

	switch e.ClassUID {
	case event.ClassCredentialOffer:
		eng.Credentials++
		addPhase(eng, PhaseCredent)
		if v, _ := e.Get("accepted"); v == true {
			eng.Authenticated = true
			addPhase(eng, PhaseAccess)
		}
	case event.ClassAuthentication:
		if v, ok := e.Get("accepted"); !ok || v == true {
			eng.Authenticated = true
			addPhase(eng, PhaseAccess)
		}
	case event.ClassCommandExecuted:
		eng.Commands++
		addPhase(eng, PhaseDiscover)
	case event.ClassFileActivity, event.ClassTokenTriggered:
		if tok := e.GetString("honeytoken"); tok != "" {
			addUnique(&eng.HoneytokensHit, tok)
			addPhase(eng, PhaseCredent)
		}
		if tok := e.GetString("token_label"); tok != "" {
			addUnique(&eng.HoneytokensHit, tok)
			addPhase(eng, PhaseCredent)
		}
	case event.ClassDetectionFinding:
		if u := e.GetString("url"); u != "" {
			addUnique(&eng.PayloadURLs, u)
		}
	}
}
