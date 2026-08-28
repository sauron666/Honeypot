package breadcrumbs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sauron666/Honeypot/internal/tokens"
)

// fakeMinter mints without a store, and records every token so a test can check
// that a crumb's carried secret is one the platform would watch for.
type fakeMinter struct {
	mu     sync.Mutex
	minted []*tokens.Token
	n      int
}

func (m *fakeMinter) Mint(typ tokens.Type, label, location string) (*tokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	id := "tok" + string(rune('a'+m.n))
	t := &tokens.Token{
		ID: id, Type: typ, Label: label, Location: location,
		Value: "VALUE-" + id, Secret: "SECRET-" + id,
	}
	// URL tokens carry the receiver URL as their value, matching the real store.
	if typ == tokens.TypeURL || typ == tokens.TypeWebImage {
		t.Value = "http://tokens.decoy/t/" + id
	}
	if typ == tokens.TypeAWSKey {
		t.Value = "AKIA" + strings.ToUpper(id) + "EXAMPLE"
	}
	m.minted = append(m.minted, t)
	return t, nil
}

func (m *fakeMinter) all() []*tokens.Token {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*tokens.Token(nil), m.minted...)
}

func linuxDecoys() []Decoy {
	return []Decoy{
		{ID: "dcy-dc01", Host: "dc01.corp.local", Service: "ssh", User: "svc_backup"},
		{ID: "dcy-sql01", Host: "sql01.corp.local", Service: "mysql"},
		{ID: "dcy-portal", Host: "portal.corp.local", Service: "http"},
	}
}

func TestEveryCrumbPointsAtADecoyAndCarriesAToken(t *testing.T) {
	m := &fakeMinter{}
	p := NewPlanner(m)
	crumbs, err := p.Plan(linuxDecoys(), Target{OS: Linux, Home: "/home/alice", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(crumbs) == 0 {
		t.Fatal("no crumbs produced")
	}
	hosts := map[string]bool{"dc01.corp.local": true, "sql01.corp.local": true, "portal.corp.local": true}
	for _, c := range crumbs {
		if c.TokenID == "" {
			t.Fatalf("%s crumb carries no token", c.Kind)
		}
		if c.Decoy == "" {
			t.Fatalf("%s crumb names no decoy", c.Kind)
		}
		// The lure has to actually mention the decoy host, or it leads nowhere.
		pointed := false
		for h := range hosts {
			if strings.Contains(c.Content, h) {
				pointed = true
			}
		}
		if !pointed {
			t.Fatalf("%s crumb mentions no decoy host:\n%s", c.Kind, c.Content)
		}
	}
}

func TestCrumbsCarryTheHoneytokenSecretSoUseIsAttributed(t *testing.T) {
	// The whole value of a breadcrumb is that using it fires. That only works if
	// the secret in the file is the token's secret the watcher looks for.
	m := &fakeMinter{}
	p := NewPlanner(m)
	crumbs, err := p.Plan(linuxDecoys(), Target{OS: Linux, Home: "/home/alice", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*tokens.Token{}
	for _, tok := range m.all() {
		byID[tok.ID] = tok
	}
	for _, c := range crumbs {
		tok := byID[c.TokenID]
		if tok == nil {
			t.Fatalf("%s references a token that was never minted", c.Kind)
		}
		// The crumb must embed either the token's value or its secret, or a
		// trigger could never be tied back to it. (winscp obscures the secret,
		// so accept the obscured form too.)
		if !strings.Contains(c.Content, tok.Value) &&
			!strings.Contains(c.Content, tok.Secret) &&
			!strings.Contains(c.Content, obscure(tok.Secret)) {
			t.Fatalf("%s crumb embeds neither the token value nor its secret:\n%s", c.Kind, c.Content)
		}
	}
}

func TestWindowsAndLinuxGetDifferentCrumbs(t *testing.T) {
	m := &fakeMinter{}
	p := NewPlanner(m)
	win := []Decoy{{ID: "d", Host: "dc01.corp.local", Service: "rdp"}}
	crumbs, err := p.Plan(win, Target{OS: Windows, Home: `C:\Users\bob`, User: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range crumbs {
		if strings.Contains(c.Kind, "bash") || strings.Contains(c.Kind, "ssh-config") {
			t.Fatalf("a Linux-only crumb (%s) was planned for Windows", c.Kind)
		}
	}
	// An rdp decoy on Windows must produce the .rdp lure.
	var haveRDP bool
	for _, c := range crumbs {
		if c.Kind == "rdp-file" {
			haveRDP = true
			if !strings.HasSuffix(c.Path, ".rdp") || !strings.Contains(c.Path, `\`) {
				t.Fatalf("rdp path does not look like a Windows path: %s", c.Path)
			}
		}
	}
	if !haveRDP {
		t.Fatal("no .rdp lure for an rdp decoy on Windows")
	}
}

func TestPlanterNeverOverwritesARealFile(t *testing.T) {
	// The invariant that matters most: a breadcrumb must never destroy a file a
	// real user already had.
	root := t.TempDir()
	pl := NewPlanter(root)

	// A non-append crumb whose target already exists must be refused.
	existing := filepath.Join(root, "Documents", "passwords.txt")
	os.MkdirAll(filepath.Dir(existing), 0o755)
	os.WriteFile(existing, []byte("REAL USER DATA\n"), 0o600)

	_, err := pl.Place(Crumb{Kind: "db-config", Path: "/.config/app/database.conf",
		Content: "x", Mode: "0600"})
	if err != nil {
		t.Fatalf("a fresh file should place fine: %v", err)
	}
	_, err = pl.Place(Crumb{Kind: "creds-file", Path: "/Documents/passwords.txt",
		Content: "LURE", Mode: "0600"}) // not Append, file exists
	if err == nil {
		t.Fatal("the planter overwrote a file that already existed")
	}
	// The real data must be intact.
	got, _ := os.ReadFile(existing)
	if string(got) != "REAL USER DATA\n" {
		t.Fatalf("a real file was modified: %q", got)
	}
}

func TestAppendPreservesExistingContentAndRemovalRestoresIt(t *testing.T) {
	root := t.TempDir()
	pl := NewPlanter(root)

	// A real ~/.ssh/config the user already had.
	cfg := filepath.Join(root, "home", "alice", ".ssh", "config")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	original := "Host github.com\n    User git\n"
	os.WriteFile(cfg, []byte(original), 0o600)

	placed, err := pl.Place(Crumb{Kind: "ssh-config", Path: "/home/alice/.ssh/config",
		Content: "Host dc01\n    HostName dc01.corp.local\n", Append: true,
		Mode: "0600", TokenID: "tokX"})
	if err != nil {
		t.Fatal(err)
	}
	if placed.Created {
		t.Fatal("appending to an existing file was recorded as a creation")
	}

	after, _ := os.ReadFile(cfg)
	if !strings.Contains(string(after), original) {
		t.Fatalf("the user's original ssh config was lost:\n%s", after)
	}
	if !strings.Contains(string(after), "dc01.corp.local") {
		t.Fatal("the appended lure is missing")
	}

	// Removal must restore the file byte-for-byte.
	m := &Manifest{Placed: []Placed{placed}}
	if err := pl.Remove(m); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(cfg)
	if string(restored) != original {
		t.Fatalf("removal did not restore the original file:\nwant %q\ngot  %q", original, restored)
	}
}

func TestRemovalDeletesFilesItCreated(t *testing.T) {
	root := t.TempDir()
	pl := NewPlanter(root)
	m := &fakeMinter{}
	p := NewPlanner(m)
	crumbs, err := p.Plan(linuxDecoys(), Target{OS: Linux, Home: "/home/alice", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := pl.PlaceAll(crumbs, "alice-laptop", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Something was written.
	var created string
	for _, pdata := range manifest.Placed {
		if pdata.Created {
			created = filepath.Join(root, strings.TrimPrefix(pdata.Path, "/"))
			break
		}
	}
	if created == "" {
		t.Skip("this plan created no whole files")
	}
	if !fileExists(created) {
		t.Fatalf("a crumb file was not actually written: %s", created)
	}
	if err := pl.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if fileExists(created) {
		t.Fatalf("removal left a created file behind: %s", created)
	}
}

func TestManifestRoundTrips(t *testing.T) {
	root := t.TempDir()
	pl := NewPlanter(root)
	m := &fakeMinter{}
	p := NewPlanner(m)
	crumbs, _ := p.Plan(linuxDecoys(), Target{OS: Linux, Home: "/home/alice", User: "alice"})
	manifest, err := pl.PlaceAll(crumbs, "alice-laptop", "alice")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "manifest.json")
	if err := SaveManifest(manifest, path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Placed) != len(manifest.Placed) || loaded.Host != "alice-laptop" {
		t.Fatalf("manifest did not round-trip: %+v", loaded)
	}
	// And removal via the reloaded manifest works, which is the real use: a
	// different invocation cleans up a previous run.
	if err := pl.Remove(loaded); err != nil {
		t.Fatal(err)
	}
}

func TestPartialFailureRollsBack(t *testing.T) {
	// If placing fails partway, nothing should be left on the machine.
	root := t.TempDir()
	pl := NewPlanter(root)

	// First crumb is fine; second targets a path that already exists as a
	// non-append, forcing a failure.
	clash := filepath.Join(root, "Documents", "x.rdp")
	os.MkdirAll(filepath.Dir(clash), 0o755)
	os.WriteFile(clash, []byte("real"), 0o600)

	crumbs := []Crumb{
		{Kind: "db-config", Path: "/.config/app/database.conf", Content: "a", Mode: "0600"},
		{Kind: "rdp-file", Path: "/Documents/x.rdp", Content: "b", Mode: "0644"}, // will clash
	}
	if _, err := pl.PlaceAll(crumbs, "h", "u"); err == nil {
		t.Fatal("a clashing plan should fail")
	}
	// The first crumb must have been rolled back.
	if fileExists(filepath.Join(root, ".config", "app", "database.conf")) {
		t.Fatal("a partial run left a file behind after rollback")
	}
	// And the real file is untouched.
	got, _ := os.ReadFile(clash)
	if string(got) != "real" {
		t.Fatalf("rollback touched a real file: %q", got)
	}
}

func TestNoCrumbForMismatchedServices(t *testing.T) {
	m := &fakeMinter{}
	p := NewPlanner(m)
	// A decoy whose service nothing in the catalogue targets on this OS.
	_, err := p.Plan([]Decoy{{ID: "d", Host: "x", Service: "telnet"}},
		Target{OS: Linux, Home: "/home/x", User: "x"})
	if err == nil {
		t.Fatal("expected no applicable crumbs for a telnet decoy")
	}
}
