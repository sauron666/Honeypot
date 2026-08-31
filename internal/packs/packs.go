// Package packs is the Deception Pack format: a signed, versioned bundle of
// deception content — personas, decoys, honeytokens and lures — that an
// operator can drop into a deployment, and that the community can contribute
// (the Sigma / Atomic Red Team model for deception).
//
// A pack is data, not code: it references personas by name and declares decoys
// and honeytokens, so it carries zero Bulgarian/American assumptions in code
// (the universality invariant). Packs are signed with the same ed25519 identity
// as the evidence vault, so an operator can trust a pack's provenance before
// applying it.
package packs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pack is a bundle of deception content.
type Pack struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Vertical    string `yaml:"vertical,omitempty" json:"vertical,omitempty"`
	Locale      string `yaml:"locale,omitempty" json:"locale,omitempty"`
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	Decoys      []PackDecoy `yaml:"decoys,omitempty" json:"decoys,omitempty"`
	Honeytokens []PackToken `yaml:"honeytokens,omitempty" json:"honeytokens,omitempty"`
	Lures       []PackLure  `yaml:"lures,omitempty" json:"lures,omitempty"`

	// Signature is a base64 ed25519 signature over the pack's canonical bytes
	// (everything except this field). Optional: an unsigned pack is usable but
	// unverified, and the CLI says so.
	Signature string `yaml:"signature,omitempty" json:"signature,omitempty"`
	// SignerFingerprint identifies the key that signed it (informational).
	SignerFingerprint string `yaml:"signer_fingerprint,omitempty" json:"signer_fingerprint,omitempty"`
}

// PackDecoy declares one decoy the pack contributes.
type PackDecoy struct {
	ID        string            `yaml:"id" json:"id"`
	Persona   string            `yaml:"persona" json:"persona"`
	Addresses []string          `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	Services  []PackService     `yaml:"services" json:"services"`
	Labels    map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// PackService is one emulated service on a decoy.
type PackService struct {
	Service string `yaml:"service" json:"service"`
	Port    int    `yaml:"port" json:"port"`
}

// PackToken declares a honeytoken the pack plants.
type PackToken struct {
	Type     string `yaml:"type" json:"type"`
	Label    string `yaml:"label" json:"label"`
	Location string `yaml:"location,omitempty" json:"location,omitempty"`
}

// PackLure is a breadcrumb the pack suggests planting on a real endpoint.
type PackLure struct {
	Kind   string `yaml:"kind" json:"kind"` // e.g. "rdp", "aws-creds", "ssh-config"
	Target string `yaml:"target" json:"target"`
	Note   string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Load reads a pack from a YAML file.
func Load(path string) (*Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("packs: read %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse decodes a pack from YAML bytes.
func Parse(raw []byte) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("packs: parse: %w", err)
	}
	return &p, nil
}

// PersonaChecker reports whether a persona name is registered. The honeyd
// package supplies the real one; validation stays decoupled from it so packs
// can be validated in tooling that does not link the whole farm.
type PersonaChecker func(name string) bool

// Validate checks structural soundness and, if a checker is given, that every
// referenced persona exists and every service is plausible.
func (p *Pack) Validate(personaExists PersonaChecker) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("packs: name is required")
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("packs: %q: version is required", p.Name)
	}
	seen := map[string]bool{}
	for _, d := range p.Decoys {
		if d.ID == "" {
			return fmt.Errorf("packs: %q: a decoy has no id", p.Name)
		}
		if seen[d.ID] {
			return fmt.Errorf("packs: %q: duplicate decoy id %q", p.Name, d.ID)
		}
		seen[d.ID] = true
		if d.Persona == "" {
			return fmt.Errorf("packs: %q: decoy %q has no persona", p.Name, d.ID)
		}
		if personaExists != nil && !personaExists(d.Persona) {
			return fmt.Errorf("packs: %q: decoy %q references unknown persona %q", p.Name, d.ID, d.Persona)
		}
		if len(d.Services) == 0 {
			return fmt.Errorf("packs: %q: decoy %q declares no services", p.Name, d.ID)
		}
		for _, s := range d.Services {
			if s.Service == "" || s.Port <= 0 || s.Port > 65535 {
				return fmt.Errorf("packs: %q: decoy %q has an invalid service %q:%d", p.Name, d.ID, s.Service, s.Port)
			}
		}
	}
	for _, t := range p.Honeytokens {
		if t.Type == "" || t.Label == "" {
			return fmt.Errorf("packs: %q: a honeytoken is missing type or label", p.Name)
		}
	}
	return nil
}

// canonicalBytes returns the deterministic bytes that a signature covers: the
// pack with its Signature and SignerFingerprint fields cleared, JSON-encoded
// with sorted keys. Two packs that differ only in signature share these bytes.
func (p *Pack) canonicalBytes() ([]byte, error) {
	clone := *p
	clone.Signature = ""
	clone.SignerFingerprint = ""
	return json.Marshal(&clone)
}

// Digest is the SHA-256 of the pack's canonical bytes (for display).
func (p *Pack) Digest() (string, error) {
	b, err := p.canonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:8]), nil
}

// Sign signs the pack with priv and records the signer fingerprint.
func (p *Pack) Sign(priv ed25519.PrivateKey, fingerprint string) error {
	b, err := p.canonicalBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, b)
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	p.SignerFingerprint = fingerprint
	return nil
}

// Verify checks the pack's signature against pub. A pack with no signature
// returns ErrUnsigned so a caller can decide whether to trust it anyway.
func (p *Pack) Verify(pub ed25519.PublicKey) error {
	if p.Signature == "" {
		return ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("packs: bad signature encoding: %w", err)
	}
	b, err := p.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return fmt.Errorf("packs: signature does not verify against this key")
	}
	return nil
}

// ErrUnsigned marks a pack that carries no signature.
var ErrUnsigned = fmt.Errorf("packs: pack is not signed")

// Summary renders a one-block human description of the pack.
func (p *Pack) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s v%s", p.Name, p.Version)
	if p.Vertical != "" || p.Locale != "" {
		fmt.Fprintf(&b, "  [%s %s]", p.Vertical, p.Locale)
	}
	b.WriteString("\n")
	if p.Description != "" {
		fmt.Fprintf(&b, "  %s\n", p.Description)
	}
	fmt.Fprintf(&b, "  %d decoys, %d honeytokens, %d lures\n",
		len(p.Decoys), len(p.Honeytokens), len(p.Lures))
	for _, d := range p.Decoys {
		svc := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			svc = append(svc, fmt.Sprintf("%s:%d", s.Service, s.Port))
		}
		sort.Strings(svc)
		fmt.Fprintf(&b, "    - %-24s %-18s %s\n", d.ID, d.Persona, strings.Join(svc, " "))
	}
	if p.Signature != "" {
		fmt.Fprintf(&b, "  signed by %s\n", p.SignerFingerprint)
	} else {
		b.WriteString("  UNSIGNED\n")
	}
	return b.String()
}
