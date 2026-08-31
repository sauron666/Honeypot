// Package feed is the Global Feed: an opt-in, anonymized threat feed built from
// high-interaction attacker observations across deployments.
//
// Privacy is the whole point. A deployment that shares to the feed contributes
// only TTPs -- the techniques an attacker used, the services they touched, the
// phases they reached, the severity they earned -- plus non-attributable
// aggregates. It never contributes anything that could identify the customer:
// no source IPs, no tenant or site ids, no honeytoken values, no raw commands,
// no full payload URLs. An Entry is deliberately built so that none of those
// can be recovered from it.
//
// The contributing deployment is identified only by a salted, non-reversible
// SourceHash -- stable across that deployment's entries so the feed can tell
// two observations came from the same place, but not linkable back to who that
// place is, and not reversible to the salt that produced it.
package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/sauron666/Honeypot/internal/engagement"
)

// Entry is one anonymized observation contributed to the feed. Every field is
// either a TTP or a non-attributable aggregate; there is deliberately nowhere
// to put a source IP, a tenant/site id, a honeytoken value, a command, or a
// full URL.
type Entry struct {
	// ID is a fresh identifier for this entry. It does NOT embed the source
	// engagement id, so two entries cannot be correlated back to one engagement.
	ID string `json:"id"`
	// PublishedAt is when this entry was anonymized for the feed.
	PublishedAt time.Time `json:"published_at"`
	// Techniques and Services are the TTPs -- what the attacker did and where.
	Techniques []string `json:"techniques,omitempty"`
	Services   []string `json:"services,omitempty"`
	// PayloadDomains carries only the host of any staging URL the attacker used
	// -- never the scheme, path, query, or credentials, which could leak a
	// customer-specific URL or a token.
	PayloadDomains []string `json:"payload_domains,omitempty"`
	// Severity is the worst severity the engagement reached, as text.
	Severity string `json:"severity"`
	// Phases is how far along the kill chain the engagement reached (a count,
	// not the phase list, to stay non-attributable).
	Phases int `json:"phases"`
	// Authenticated reports whether the attacker got past a credential gate.
	Authenticated bool `json:"authenticated"`
	// SourceHash is a salted, non-reversible prefix identifying the contributing
	// DEPLOYMENT -- stable across its entries, not linkable to identity, not
	// reversible to the salt.
	SourceHash string `json:"source_hash"`
}

// Anonymize turns one engagement into a feed Entry, stripping everything that
// could identify the customer. It copies only TTPs and safe aggregates.
//
// deploymentSalt is a secret, per-deployment value. It never appears in the
// Entry; only a truncated SHA-256 of it does, so the contributing deployment is
// stable and comparable but not reversible or attributable.
func Anonymize(eng engagement.Engagement, deploymentSalt string) Entry {
	e := Entry{
		PublishedAt:   time.Now().UTC(),
		Severity:      eng.MaxSeverity.String(),
		Phases:        len(eng.Phases),
		Authenticated: eng.Authenticated,
		SourceHash:    sourceHash(deploymentSalt),
	}

	// Techniques and Services are TTPs -- safe to share. Copy into fresh slices
	// so the Entry never aliases the engagement's backing arrays.
	if len(eng.Techniques) > 0 {
		e.Techniques = append([]string(nil), eng.Techniques...)
	}
	if len(eng.Services) > 0 {
		e.Services = append([]string(nil), eng.Services...)
	}

	// PayloadURLs -> PayloadDomains: keep only the host. A URL that will not
	// parse, or that yields no host, is dropped entirely rather than risk
	// leaking a raw customer-specific URL.
	seen := map[string]bool{}
	for _, raw := range eng.PayloadURLs {
		host := domainOf(raw)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		e.PayloadDomains = append(e.PayloadDomains, host)
	}

	// ID is derived from the technique set and the timestamp, never from
	// eng.ID -- embedding the engagement id would let the feed be correlated
	// back to a specific deployment's records.
	e.ID = freshID(e.Techniques, e.PublishedAt)
	return e
}

// domainOf extracts just the host from a payload URL, dropping scheme, path,
// query, fragment, and any embedded credentials. It returns "" for anything it
// cannot safely reduce to a bare host, so a caller never leaks a raw URL.
func domainOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	// url.Hostname() strips any port and userinfo, returning only the host.
	return u.Hostname()
}

// sourceHash returns the first 12 hex chars of sha256(salt): deterministic per
// deployment, stable across its entries, and not reversible to the salt.
func sourceHash(salt string) string {
	sum := sha256.Sum256([]byte(salt))
	return hex.EncodeToString(sum[:])[:12]
}

// freshID mints an entry id that does not embed the source engagement id. It
// mixes the technique set, the publish time, and a random nonce so distinct
// entries never collide even within the same nanosecond.
func freshID(techniques []string, at time.Time) string {
	h := sha256.New()
	for _, t := range techniques {
		h.Write([]byte(t))
		h.Write([]byte{0})
	}
	fmt.Fprintf(h, "|%d|", at.UnixNano())
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err == nil {
		h.Write(nonce[:])
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Feed is a signed, versioned collection of anonymized entries.
type Feed struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Entries     []Entry   `json:"entries"`
	// Signature is a base64 ed25519 signature over the feed's canonical bytes
	// (everything except this field and SignerFingerprint).
	Signature string `json:"signature,omitempty"`
	// SignerFingerprint identifies the key that signed it (informational).
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
}

// ErrUnsigned marks a feed that carries no signature.
var ErrUnsigned = fmt.Errorf("feed: feed is not signed")

// canonicalBytes returns the deterministic bytes a signature covers: the feed
// with its Signature and SignerFingerprint cleared, JSON-encoded. Two feeds
// that differ only in signature share these bytes.
func (f *Feed) canonicalBytes() ([]byte, error) {
	clone := *f
	clone.Signature = ""
	clone.SignerFingerprint = ""
	return json.Marshal(&clone)
}

// Sign signs the feed with priv and records the signer fingerprint.
func (f *Feed) Sign(priv ed25519.PrivateKey, fp string) error {
	b, err := f.canonicalBytes()
	if err != nil {
		return err
	}
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	f.SignerFingerprint = fp
	return nil
}

// Verify checks the feed's signature against pub. A feed with no signature
// returns ErrUnsigned so a caller can decide whether to trust it anyway.
func (f *Feed) Verify(pub ed25519.PublicKey) error {
	if f.Signature == "" {
		return ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return fmt.Errorf("feed: bad signature encoding: %w", err)
	}
	b, err := f.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return fmt.Errorf("feed: signature does not verify against this key")
	}
	return nil
}

// Marshal encodes the feed as indented JSON.
func (f *Feed) Marshal() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

// ParseFeed decodes a feed from JSON bytes.
func ParseFeed(raw []byte) (*Feed, error) {
	var f Feed
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("feed: parse: %w", err)
	}
	return &f, nil
}

// Merge appends other's entries into f, de-duplicating by Entry.ID. Merging
// changes the contents, so a merged feed's existing signature no longer covers
// it: a caller that needs provenance should re-sign after merging.
func (f *Feed) Merge(other *Feed) {
	if other == nil {
		return
	}
	have := map[string]bool{}
	for _, e := range f.Entries {
		have[e.ID] = true
	}
	for _, e := range other.Entries {
		if have[e.ID] {
			continue
		}
		have[e.ID] = true
		f.Entries = append(f.Entries, e)
	}
}
