package tokens

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sauron666/Honeypot/internal/event"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	s, err := NewStore(path, "http://decoy.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestMintProducesPlausibleValues(t *testing.T) {
	s, _ := newStore(t)

	aws, err := s.Mint(TypeAWSKey, "finance share key", "\\\\FS01\\finance\\backup.ps1")
	if err != nil {
		t.Fatal(err)
	}
	// The shape matters: a key that does not look like an AWS key is one an
	// attacker walks past, and a real one would be a liability.
	if !strings.HasPrefix(aws.Value, "AKIA") || len(aws.Value) != 20 {
		t.Fatalf("AWS key id %q does not look like one", aws.Value)
	}
	if len(aws.Secret) < 32 {
		t.Fatalf("AWS secret is only %d characters", len(aws.Secret))
	}

	url, err := s.Mint(TypeURL, "canary link", "email signature")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url.Value, "http://decoy.internal:8080/t/") {
		t.Fatalf("callback URL = %q", url.Value)
	}

	// Two tokens of the same type must never collide.
	other, _ := s.Mint(TypeAWSKey, "second", "")
	if other.Value == aws.Value || other.Secret == aws.Secret {
		t.Fatal("minted tokens collided")
	}

	if _, err := s.Mint("teapot", "x", ""); err == nil {
		t.Fatal("an unknown token type must be rejected")
	}
}

func TestStorePersistsAcrossRestart(t *testing.T) {
	s, path := newStore(t)
	tok, _ := s.Mint(TypeAPIToken, "ci token", "gitlab-ci.yml")

	// The registry is what lets us recognise a trigger when it arrives; losing
	// it means the token still exists but no longer means anything.
	s2, err := NewStore(path, "http://decoy.internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(tok.ID)
	if !ok {
		t.Fatal("token did not survive a restart")
	}
	if got.Value != tok.Value {
		t.Fatalf("value changed across restart: %q vs %q", got.Value, tok.Value)
	}
	if hits := s2.FindInText("here is " + tok.Value + " somewhere"); len(hits) != 1 {
		t.Fatal("the value index was not rebuilt on load")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token registry mode = %o, want 600", perm)
	}
}

func TestFireCountsTriggers(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeURL, "link", "")

	for i := 1; i <= 3; i++ {
		fired, ok := s.Fire(tok.ID)
		if !ok {
			t.Fatal("Fire on a known token must succeed")
		}
		if fired.Triggers != i {
			t.Fatalf("trigger count = %d, want %d", fired.Triggers, i)
		}
	}
	if _, ok := s.Fire("nosuchtoken"); ok {
		t.Fatal("Fire on an unknown token must fail")
	}
}

func TestFindInTextIgnoresShortValues(t *testing.T) {
	s, _ := newStore(t)
	cred, _ := s.Mint(TypeCredential, "service account", "")

	// The username "svc_backup" is short and could appear in ordinary text.
	// Matching on it would produce exactly the false positives honeytokens
	// exist to avoid; the paired secret is what gets watched.
	if hits := s.FindInText("the svc_backup account runs the nightly job"); len(hits) != 0 {
		t.Fatalf("short value matched: %v", hits)
	}
	if hits := s.FindInText("password is " + cred.Secret); len(hits) != 1 {
		t.Fatalf("the secret must be watched, got %d hits", len(hits))
	}
}

func TestFindInTextIsCaseInsensitive(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeAWSKey, "k", "")
	if hits := s.FindInText("aws_access_key_id = " + strings.ToLower(tok.Value)); len(hits) != 1 {
		t.Fatal("token matching must ignore case: attackers lowercase things")
	}
}

func TestDeleteRemovesFromIndex(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeAPIToken, "temp", "")
	if err := s.Delete(tok.ID); err != nil {
		t.Fatal(err)
	}
	if hits := s.FindInText("value " + tok.Value); len(hits) != 0 {
		t.Fatal("a deleted token must stop matching")
	}
	if err := s.Delete(tok.ID); err == nil {
		t.Fatal("deleting twice must fail")
	}
}

func TestWatcherFiresOnObservedValue(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeAWSKey, "finance key", "\\\\FS01\\finance")

	var (
		mu   sync.Mutex
		seen []*event.Event
	)
	w := NewWatcher(s, "acme", "dc1", func(_ context.Context, e *event.Event) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e)
	})

	// The attacker pastes the planted key into a decoy shell.
	ev := event.New(event.ClassCommandExecuted, 1, event.SeverityMedium, event.PlaneHoneyd)
	ev.Mirage.DecoyID = "dcy-web01"
	ev.Mirage.Service = "ssh"
	ev.Mirage.EngagementID = "eng_1"
	ev.WithSrc("198.51.100.7", 4444)
	ev.Set("command", "aws configure set aws_access_key_id "+tok.Value)
	w.Handle(context.Background(), ev)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("watcher produced %d events, want 1", len(seen))
	}
	got := seen[0]
	if got.ClassUID != event.ClassTokenTriggered {
		t.Fatalf("class = %s", got.ClassUID)
	}
	if got.SeverityID != event.SeverityCritical {
		t.Fatalf("severity = %s, want critical", got.SeverityID)
	}
	// The trigger must carry where the token was planted: that is what turns
	// an alert into an investigation.
	if got.GetString("token_location") != "\\\\FS01\\finance" {
		t.Fatalf("location = %q", got.GetString("token_location"))
	}
	if got.Mirage.EngagementID != "eng_1" {
		t.Fatal("trigger must join the engagement that produced it")
	}
	if got.GetString("trigger_method") != "observed" {
		t.Fatalf("method = %q", got.GetString("trigger_method"))
	}
}

func TestWatcherDoesNotLoopOnItsOwnEvents(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeAWSKey, "k", "")

	var count int
	w := NewWatcher(s, "acme", "dc1", func(context.Context, *event.Event) { count++ })

	// A trigger event names the token; scanning it would fire the token again,
	// and again, forever.
	trigger := event.New(event.ClassTokenTriggered, 1, event.SeverityCritical, event.PlaneToken)
	trigger.Set("token_id", tok.ID).Set("value", tok.Value)
	w.Handle(context.Background(), trigger)

	if count != 0 {
		t.Fatal("the watcher must ignore token trigger events")
	}
}

func TestGenerateDocxIsAValidPackageWithTheCanary(t *testing.T) {
	s, _ := newStore(t)
	tok, _ := s.Mint(TypeOfficeDoc, "Salaries 2026", "\\\\FS01\\hr")

	doc, err := GenerateDocx(tok, "Salaries 2026", "Confidential.")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatalf("the generated file is not a valid package: %v", err)
	}

	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	for _, required := range []string{
		"[Content_Types].xml", "_rels/.rels", "word/document.xml",
		"word/settings.xml", "word/_rels/settings.xml.rels",
	} {
		if _, ok := files[required]; !ok {
			t.Errorf("missing %s: the document will not open", required)
		}
	}
	rels := files["word/_rels/settings.xml.rels"]
	if !strings.Contains(rels, tok.Value) {
		t.Error("the callback URL is not in the document")
	}
	if !strings.Contains(rels, `TargetMode="External"`) {
		t.Error("the relationship must be external, or nothing is fetched")
	}
	if !strings.Contains(rels, "attachedTemplate") {
		t.Error("the canary relies on the attached template relationship")
	}
	// A canary document must contain nothing executable: it is bait, not malware.
	for name, content := range files {
		if strings.Contains(strings.ToLower(content), "vbaproject") ||
			strings.Contains(strings.ToLower(name), ".bin") {
			t.Errorf("%s looks like it carries executable content", name)
		}
	}
}
