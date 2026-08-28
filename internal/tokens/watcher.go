package tokens

import (
	"context"
	"fmt"
	"strings"

	"github.com/sauron666/Honeypot/internal/event"
)

// Watcher fires tokens that appear in attacker activity rather than in a
// callback.
//
// This is the half of honeytoken detection that nobody ships: a planted AWS key
// does not only fire when it is used against AWS. If the attacker pastes it
// into a decoy, greps for it, or uploads a file containing it, we see the value
// go past and we know which planted secret they took and from where.
type Watcher struct {
	store  *Store
	tenant string
	site   string
	emit   func(context.Context, *event.Event)

	// maxScan bounds how much of an event we search. Attackers upload large
	// files; scanning all of one is not worth stalling the pipeline for.
	maxScan int
}

// NewWatcher builds a watcher.
func NewWatcher(store *Store, tenant, site string, emit func(context.Context, *event.Event)) *Watcher {
	return &Watcher{store: store, tenant: tenant, site: site, emit: emit, maxScan: 256 * 1024}
}

// Handle inspects one event. It is safe to subscribe directly to the bus.
func (w *Watcher) Handle(ctx context.Context, e *event.Event) {
	// Never scan our own trigger events: they contain the token id and would
	// otherwise cause an endless cascade.
	if e.ClassUID == event.ClassTokenTriggered {
		return
	}
	text := w.textOf(e)
	if text == "" {
		return
	}
	for _, t := range w.store.FindInText(text) {
		fired, ok := w.store.Fire(t.ID)
		if !ok {
			continue
		}
		src := ""
		if e.Src != nil {
			src = e.Src.IP
		}
		trigger := Trigger{
			TokenID: t.ID, Token: fired, SrcIP: src, How: "observed",
			Context: fmt.Sprintf("seen in %s on decoy %s (%s)",
				e.ClassUID, e.Mirage.DecoyID, e.Mirage.Service),
		}
		ev := TriggerEvent(fired, trigger, w.tenant, w.site)
		ev.Mirage.DecoyID = e.Mirage.DecoyID
		ev.Mirage.Service = e.Mirage.Service
		ev.Mirage.EngagementID = e.Mirage.EngagementID
		ev.Set("observed_in_event", e.Metadata.UID)
		if w.emit != nil {
			w.emit(ctx, ev)
		}
	}
}

// textOf gathers the attacker-supplied strings in an event.
func (w *Watcher) textOf(e *event.Event) string {
	var b strings.Builder
	b.WriteString(e.Message)
	for _, v := range e.Data {
		if b.Len() > w.maxScan {
			break
		}
		switch s := v.(type) {
		case string:
			b.WriteByte('\n')
			b.WriteString(s)
		case []string:
			for _, x := range s {
				b.WriteByte('\n')
				b.WriteString(x)
			}
		}
	}
	return b.String()
}
