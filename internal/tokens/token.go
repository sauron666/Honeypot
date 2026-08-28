// Package tokens mints and tracks honeytokens: bait that needs no
// infrastructure at all.
//
// A honeytoken is a credential, file or URL that exists for exactly one reason
// -- so that touching it is unambiguous. There is no legitimate process that
// reads a planted AWS key or fetches a canary URL, so unlike almost everything
// else in security, a trigger needs no interpretation.
package tokens

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sauron666/Honeypot/internal/event"
)

// Type is a honeytoken kind.
type Type string

const (
	TypeURL        Type = "url"           // a canary URL, fetched by whoever found it
	TypeWebImage   Type = "web-image"     // a remote image to embed in a document
	TypeOfficeDoc  Type = "office-doc"    // a .docx that phones home when opened
	TypeAWSKey     Type = "aws-key"       // AWS access key pair
	TypeAPIToken   Type = "api-token"     // generic bearer token
	TypeDBString   Type = "db-connection" // database connection string
	TypeSSHKey     Type = "ssh-key"       // private key file
	TypeCredential Type = "credential"    // username and password pair
)

// AllTypes lists every mintable type.
func AllTypes() []Type {
	return []Type{TypeURL, TypeWebImage, TypeOfficeDoc, TypeAWSKey,
		TypeAPIToken, TypeDBString, TypeSSHKey, TypeCredential}
}

// Token is one piece of bait.
type Token struct {
	ID    string `json:"id"`
	Type  Type   `json:"type"`
	Label string `json:"label"`

	// Value is what an attacker sees and may carry away: a URL, an access key
	// id, a username. It is the string the watcher looks for.
	Value string `json:"value"`
	// Secret is the paired half where a type has one (an AWS secret key, a
	// password). It is also watched.
	Secret string `json:"secret,omitempty"`

	// Location records where the token was planted, which is what turns a
	// trigger into an investigation: "this key was in the finance file share".
	Location string `json:"location,omitempty"`
	Notes    string `json:"notes,omitempty"`

	CreatedAt     time.Time `json:"created_at"`
	LastTriggered time.Time `json:"last_triggered,omitempty"`
	Triggers      int       `json:"triggers"`
}

// Trigger describes one use of a token.
type Trigger struct {
	TokenID   string
	Token     *Token
	SrcIP     string
	UserAgent string
	How       string // "callback" or "observed"
	Context   string
}

// Store holds minted tokens and persists them.
type Store struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]*Token
	// byValue indexes the strings the watcher scans for, lowercased.
	byValue map[string]*Token
	baseURL string
}

// NewStore opens or creates a token store. baseURL is the address an attacker
// can reach, which is where callback URLs point.
func NewStore(path, baseURL string) (*Store, error) {
	s := &Store{
		path: path, tokens: map[string]*Token{}, byValue: map[string]*Token{},
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("tokens: read %s: %w", s.path, err)
	}
	var list []*Token
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("tokens: parse %s: %w", s.path, err)
	}
	for _, t := range list {
		s.tokens[t.ID] = t
		s.index(t)
	}
	return nil
}

func (s *Store) index(t *Token) {
	if t.Value != "" {
		s.byValue[strings.ToLower(t.Value)] = t
	}
	if t.Secret != "" {
		s.byValue[strings.ToLower(t.Secret)] = t
	}
}

func (s *Store) saveLocked() error {
	list := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })

	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	// Write via a temporary file so a crash cannot leave a half-written
	// registry: losing the token list means losing the ability to recognise a
	// trigger when it arrives.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Mint creates a token of the given type.
func (s *Store) Mint(typ Type, label, location string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strings.ToLower(randomString(10))
	t := &Token{ID: id, Type: typ, Label: label, Location: location, CreatedAt: time.Now()}

	switch typ {
	case TypeURL:
		t.Value = fmt.Sprintf("%s/t/%s", s.baseURL, id)
		t.Notes = "fetching this URL triggers the token"
	case TypeWebImage:
		t.Value = fmt.Sprintf("%s/t/%s/logo.png", s.baseURL, id)
		t.Notes = "embed in a document; opening it fetches the image"
	case TypeOfficeDoc:
		t.Value = fmt.Sprintf("%s/t/%s/header.png", s.baseURL, id)
		t.Notes = "generated .docx fetches this image when opened"
	case TypeAWSKey:
		// The shape matters: a key that does not look like an AWS key will not
		// be picked up, and one that is a real key would be a liability.
		t.Value = "AKIA" + strings.ToUpper(randomString(16))
		t.Secret = randomSecret(40)
		t.Notes = "not a real AWS key; alerts when the value is seen or used against a decoy"
	case TypeAPIToken:
		t.Value = "mrg_" + randomSecret(32)
	case TypeDBString:
		user := "svc_reporting"
		pass := randomSecret(18)
		t.Value = fmt.Sprintf("Server=sql01;Database=billing;User Id=%s;Password=%s;", user, pass)
		t.Secret = pass
	case TypeSSHKey:
		t.Value = "MIRAGE-SSH-" + randomSecret(24)
		t.Notes = "embed inside a private key file; the marker is what we watch for"
	case TypeCredential:
		t.Value = "svc_backup"
		t.Secret = randomSecret(16)
	default:
		return nil, fmt.Errorf("tokens: unknown type %q (have: %v)", typ, AllTypes())
	}

	s.tokens[id] = t
	s.index(t)
	if err := s.saveLocked(); err != nil {
		delete(s.tokens, id)
		return nil, err
	}
	return t, nil
}

// Get returns a token by id.
func (s *Store) Get(id string) (*Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	return t, ok
}

// List returns all tokens, newest first.
func (s *Store) List() []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Delete removes a token.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return fmt.Errorf("tokens: no such token %q", id)
	}
	delete(s.tokens, id)
	delete(s.byValue, strings.ToLower(t.Value))
	if t.Secret != "" {
		delete(s.byValue, strings.ToLower(t.Secret))
	}
	return s.saveLocked()
}

// Fire records a trigger against a token.
func (s *Store) Fire(id string) (*Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, false
	}
	t.Triggers++
	t.LastTriggered = time.Now()
	_ = s.saveLocked()
	cp := *t
	return &cp, true
}

// FindInText looks for any minted token value inside a blob of attacker-supplied
// text. This is the second way a token fires: not because the attacker fetched
// a URL, but because they carried the value somewhere we can see -- pasting a
// planted key into a decoy, or grepping for it.
//
// Values shorter than minWatchLength are ignored: a short token would match
// ordinary text and produce exactly the false positives honeytokens exist to
// avoid.
func (s *Store) FindInText(text string) []*Token {
	if len(text) == 0 {
		return nil
	}
	lower := strings.ToLower(text)

	s.mu.RLock()
	defer s.mu.RUnlock()

	var hits []*Token
	seen := map[string]bool{}
	for value, t := range s.byValue {
		if len(value) < minWatchLength {
			continue
		}
		if strings.Contains(lower, value) && !seen[t.ID] {
			seen[t.ID] = true
			cp := *t
			hits = append(hits, &cp)
		}
	}
	return hits
}

// minWatchLength is the shortest token value the watcher will search for.
const minWatchLength = 12

// Stats summarises the token inventory.
func (s *Store) Stats() (total, triggered int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		total++
		if t.Triggers > 0 {
			triggered++
		}
	}
	return
}

// TriggerEvent builds the event for a fired token.
func TriggerEvent(t *Token, tr Trigger, tenant, site string) *event.Event {
	e := event.New(event.ClassTokenTriggered, 1, event.SeverityCritical, event.PlaneToken)
	e.Mirage.TenantID, e.Mirage.SiteID = tenant, site
	e.Mirage.Service = "honeytoken"
	e.WithSrc(tr.SrcIP, 0).
		WithMessage("honeytoken %q triggered (%s): %s", t.Label, t.Type, tr.How).
		WithAttack(event.Technique{Tactic: "TA0006", Technique: "T1552", Name: "Unsecured Credentials"})
	e.Set("token_id", t.ID).
		Set("token_type", string(t.Type)).
		Set("token_label", t.Label).
		Set("token_location", t.Location).
		Set("trigger_method", tr.How).
		Set("triggers_total", t.Triggers)
	if tr.UserAgent != "" {
		e.Set("user_agent", tr.UserAgent)
	}
	if tr.Context != "" {
		e.Set("context", tr.Context)
	}
	return e
}

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("tokens: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// randomSecret produces a high-entropy value that looks like a real secret.
func randomSecret(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("tokens: crypto/rand unavailable: " + err.Error())
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if len(enc) > n {
		enc = enc[:n]
	}
	return enc
}
