// Package breadcrumbs plants lures on real endpoints that lead into the decoys.
//
// Every other part of MIRAGE waits for an attacker to find a decoy. This part
// goes the other way: it seeds the machines an attacker actually lands on --
// a developer's laptop, a jump box, a domain-joined workstation -- with the
// artefacts they harvest first. A saved .rdp file, an ~/.aws/credentials
// profile, a line of shell history, a WinSCP session. Each one points at a
// decoy and carries a honeytoken, so the moment the attacker follows it or
// even just reads the credential, the platform knows -- and knows which
// endpoint the trail started on.
//
// This is the one component that writes to machines MIRAGE does not own, so its
// invariants are stricter than anywhere else:
//
//   - It never plants a real secret. Every credential a crumb carries is a
//     registered honeytoken that unlocks only a decoy.
//   - It never overwrites or truncates an existing file. It creates new files,
//     or appends a delimited, clearly-reversible block to ones that already
//     exist; a real ~/.bash_history keeps every line it had.
//   - It records everything it placed in a manifest, so removal reverses
//     exactly what was planted and touches nothing else.
//   - It dials out only to mint tokens from the configured director. The crumbs
//     point at decoys, never back at the agent.
//
// A breadcrumb that got any of these wrong would not be deception; it would be
// the platform vandalising, or worse leaking real secrets onto, a machine it
// was meant to protect.
package breadcrumbs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sauron666/Honeypot/internal/tokens"
)

// OS is the family of endpoint a crumb is written for. The same lure looks
// native in different places -- shell history lives in ~/.bash_history on Linux
// and in a PowerShell transcript on Windows -- so a crumb declares where it
// belongs and the planner only emits the ones that fit the target.
type OS string

const (
	Linux   OS = "linux"
	Windows OS = "windows"
	Any     OS = "any"
)

// Decoy is the destination a crumb points at: a real decoy the platform is
// already serving. The breadcrumb makes an attacker want to reach it.
type Decoy struct {
	// ID ties a triggered token back to the decoy in the console.
	ID string `yaml:"id" json:"id"`
	// Host is the name an attacker will type or click: dc01.corp.local, the
	// address of a windows/dc decoy, say.
	Host string `yaml:"host" json:"host"`
	// Service is what lives there: rdp, ssh, mssql, smb, http. It decides which
	// crumbs make sense -- an .rdp file for an rdp host, an ~/.ssh/config block
	// for an ssh host.
	Service string `yaml:"service" json:"service"`
	// User is the plausible account name the lure suggests, e.g. "svc_backup".
	// Empty lets the crumb pick one.
	User string `yaml:"user" json:"user"`
}

// Target describes the endpoint being seeded.
type Target struct {
	OS OS
	// Home is the user profile directory the crumbs are written under, e.g.
	// /home/alice or C:\Users\alice.
	Home string
	// User is the local account, used where a lure names the current user.
	User string
}

// Crumb is one lure, fully rendered and ready to place.
type Crumb struct {
	// Kind is the catalogue entry that produced it, for the manifest and logs.
	Kind string `json:"kind"`
	// Path is where it goes, already resolved under the target's home.
	Path string `json:"path"`
	// Content is the exact bytes to write.
	Content string `json:"content"`
	// Append is true when the content is a delimited block added to a file that
	// may already exist, rather than a whole new file. It decides whether the
	// planter creates or appends, and how removal reverses it.
	Append bool `json:"append"`
	// Mode is the unix permission for a newly created file, e.g. "0600". Secrets
	// get 0600 so they look like something worth protecting -- and so a crumb
	// never widens the permissions of anything.
	Mode string `json:"mode"`
	// TokenID is the honeytoken this crumb carries, so a trigger names the crumb.
	TokenID string `json:"token_id"`
	// Decoy is the id of the decoy it points at.
	Decoy string `json:"decoy"`
	// Explain is a one-line human description for the plan output.
	Explain string `json:"explain"`
}

// Minter mints honeytokens. tokens.Store satisfies it; tests supply a fake.
//
// Breadcrumbs depend on the token abstraction, not on how tokens are stored or
// watched, so the planner can run offline in a test and against a live director
// in production without changing.
type Minter interface {
	Mint(typ tokens.Type, label, location string) (*tokens.Token, error)
}

// Planner turns decoys into crumbs for a target.
type Planner struct {
	minter Minter
	// catalog is the set of crumb generators, in a stable order so a plan is
	// reproducible.
	catalog []generator
}

// generator produces zero or one crumb for a (decoy, target). Returning a nil
// crumb means "not applicable here" -- an .rdp generator says nothing about an
// ssh decoy, and a bash-history generator says nothing on Windows.
type generator struct {
	kind string
	// services the generator applies to; empty means any service.
	services []string
	os       OS
	build    func(p *Planner, d Decoy, tgt Target) (*Crumb, error)
}

// NewPlanner builds a planner over the given minter.
func NewPlanner(m Minter) *Planner {
	p := &Planner{minter: m}
	p.catalog = defaultCatalog()
	return p
}

// Plan renders every applicable crumb for the decoys and target, minting a
// token for each. The order is stable: decoys in the order given, generators in
// catalogue order, so two runs of the same plan produce the same list.
func (p *Planner) Plan(decoys []Decoy, tgt Target) ([]Crumb, error) {
	if tgt.Home == "" {
		return nil, fmt.Errorf("breadcrumbs: target home directory is required")
	}
	if tgt.OS == "" {
		return nil, fmt.Errorf("breadcrumbs: target OS is required")
	}
	var out []Crumb
	for _, d := range decoys {
		if d.Host == "" || d.Service == "" {
			return nil, fmt.Errorf("breadcrumbs: decoy %q needs a host and a service", d.ID)
		}
		for _, g := range p.catalog {
			if !g.appliesTo(d, tgt) {
				continue
			}
			c, err := g.build(p, d, tgt)
			if err != nil {
				return nil, fmt.Errorf("breadcrumbs: %s for %s: %w", g.kind, d.Host, err)
			}
			if c != nil {
				out = append(out, *c)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("breadcrumbs: no crumb applies to these decoys on %s; "+
			"check that the decoys' services (rdp, ssh, mssql, smb, http) match the target OS", tgt.OS)
	}
	return out, nil
}

func (g generator) appliesTo(d Decoy, tgt Target) bool {
	if g.os != Any && g.os != tgt.OS {
		return false
	}
	if len(g.services) == 0 {
		return true
	}
	for _, s := range g.services {
		if strings.EqualFold(s, d.Service) {
			return true
		}
	}
	return false
}

// Kinds lists the catalogue entries, for documentation and the CLI.
func (p *Planner) Kinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range p.catalog {
		if !seen[g.kind] {
			seen[g.kind] = true
			out = append(out, g.kind)
		}
	}
	sort.Strings(out)
	return out
}

// userOr returns the decoy's suggested user, or a plausible default.
func userOr(d Decoy, def string) string {
	if d.User != "" {
		return d.User
	}
	return def
}
