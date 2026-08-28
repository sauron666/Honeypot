package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sauron666/Honeypot/internal/honeyd"
)

// Change is one difference between what is running and what a manifest asks for.
type Change struct {
	Action  string `json:"action"` // add, remove, replace
	Key     string `json:"key"`    // service/address:port
	DecoyID string `json:"decoy_id"`
	Persona string `json:"persona"`
	Detail  string `json:"detail,omitempty"`
}

// Plan is the result of comparing a manifest against a running deployment.
//
// This is the first half of deception-as-code: an operator should be able to
// see exactly what applying a manifest would do before it does it. Deception
// changes what an attacker sees, so a surprise here is worse than a surprise in
// most infrastructure.
type Plan struct {
	Changes []Change `json:"changes"`
	// RequiresRestart lists settings that cannot be changed in place, so that
	// an apply never silently half-works.
	RequiresRestart []string `json:"requires_restart,omitempty"`
	Unchanged       int      `json:"unchanged"`
}

// Empty reports whether applying the manifest would change nothing.
func (p Plan) Empty() bool { return len(p.Changes) == 0 && len(p.RequiresRestart) == 0 }

// Summary renders a one-line description.
func (p Plan) Summary() string {
	if p.Empty() {
		return fmt.Sprintf("no changes; %d endpoint(s) already match", p.Unchanged)
	}
	var add, remove, replace int
	for _, c := range p.Changes {
		switch c.Action {
		case "add":
			add++
		case "remove":
			remove++
		case "replace":
			replace++
		}
	}
	parts := []string{}
	if add > 0 {
		parts = append(parts, fmt.Sprintf("%d to add", add))
	}
	if replace > 0 {
		parts = append(parts, fmt.Sprintf("%d to replace", replace))
	}
	if remove > 0 {
		parts = append(parts, fmt.Sprintf("%d to remove", remove))
	}
	if len(p.RequiresRestart) > 0 {
		parts = append(parts, fmt.Sprintf("%d needing a restart", len(p.RequiresRestart)))
	}
	return strings.Join(parts, ", ") + fmt.Sprintf("; %d unchanged", p.Unchanged)
}

// listenerKey identifies an endpoint by what it occupies on the network.
func listenerKey(l honeyd.ListenerConfig, bind string) string {
	host := l.Address
	if host == "" {
		host = bind
	}
	return fmt.Sprintf("%s/%s:%d", l.Service, host, l.Port)
}

// DiffListeners compares a running listener set against a desired one.
func DiffListeners(current, desired []honeyd.ListenerConfig, bind string) Plan {
	var p Plan
	cur := map[string]honeyd.ListenerConfig{}
	for _, l := range current {
		cur[listenerKey(l, bind)] = l
	}
	want := map[string]honeyd.ListenerConfig{}
	for _, l := range desired {
		want[listenerKey(l, bind)] = l
	}

	for key, l := range want {
		old, running := cur[key]
		switch {
		case !running:
			p.Changes = append(p.Changes, Change{
				Action: "add", Key: key, DecoyID: l.DecoyID, Persona: l.Persona,
			})
		case old.Persona != l.Persona || old.DecoyID != l.DecoyID:
			// The address is the same but the identity behind it is not, which
			// an attacker who has already looked would notice.
			p.Changes = append(p.Changes, Change{
				Action: "replace", Key: key, DecoyID: l.DecoyID, Persona: l.Persona,
				Detail: fmt.Sprintf("was %s/%s, becomes %s/%s",
					old.DecoyID, old.Persona, l.DecoyID, l.Persona),
			})
		default:
			p.Unchanged++
		}
	}
	for key, l := range cur {
		if _, keep := want[key]; !keep {
			p.Changes = append(p.Changes, Change{
				Action: "remove", Key: key, DecoyID: l.DecoyID, Persona: l.Persona,
			})
		}
	}

	sort.Slice(p.Changes, func(i, j int) bool {
		if p.Changes[i].Action != p.Changes[j].Action {
			return p.Changes[i].Action < p.Changes[j].Action
		}
		return p.Changes[i].Key < p.Changes[j].Key
	})
	return p
}

// Immutable lists the settings that only take effect at startup, with the
// reason, so that a plan can say plainly what an apply will not do.
func Immutable(running, desired *Config) []string {
	var out []string
	check := func(name, was, becomes, why string) {
		if was != becomes {
			out = append(out, fmt.Sprintf("%s: %q -> %q (%s)", name, was, becomes, why))
		}
	}
	check("tenant", running.Tenant, desired.Tenant,
		"every stored event carries the tenant; changing it would split the evidence in two")
	check("site", running.Site, desired.Site,
		"every stored event carries the site")
	check("data_dir", running.DataDir, desired.DataDir,
		"the evidence chain and the deployment seed live there")
	check("api.listen", running.API.Listen, desired.API.Listen,
		"the management listener is bound at startup")
	check("honeyd.bind", running.Honeyd.Bind, desired.Honeyd.Bind,
		"changing the bind address would move every decoy at once")
	check("storage.evidence_file", running.Storage.EvidenceFile, desired.Storage.EvidenceFile,
		"the hash chain is anchored to the current file")
	return out
}
