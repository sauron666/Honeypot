// Package catalog is the image library for full-OS decoys.
//
// A deception estate is only as convincing as the machines it puts in front of
// an attacker. Operators want to drop in their own images — a hardened Ubuntu,
// a deliberately vulnerable box modelled on a CTF machine (HackTheBox, VulnHub),
// a Windows build — tag them by how hard they are to own (easy/medium/hard/
// insane), and swap them freely. Before an image becomes a decoy it must be
// SANITISED: CTF flags removed, known credentials reset, a tracking watermark
// embedded. This package is the registry and the sanitisation planner; the
// hypervisor drivers consume the registered images as decoy templates.
//
// The registry stores metadata only and references images by path, so adding a
// 20 GB image costs a checksum, not a copy. It never deletes an image file: on
// Remove it forgets the entry, leaving the bytes to the operator.
package catalog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Difficulty is how hard a decoy is meant to be to compromise. It sets attacker
// expectations and lets an operator build a graded honeynet: an easy box to
// catch the noisy, an insane one to hold the patient.
type Difficulty string

const (
	Easy   Difficulty = "easy"
	Medium Difficulty = "medium"
	Hard   Difficulty = "hard"
	Insane Difficulty = "insane"
)

// Valid reports whether d is one of the known tiers.
func (d Difficulty) Valid() bool {
	switch d {
	case Easy, Medium, Hard, Insane:
		return true
	}
	return false
}

// Format is the image container format, detected from the file.
type Format string

const (
	FormatISO   Format = "iso"
	FormatOVA   Format = "ova"
	FormatOVF   Format = "ovf"
	FormatQCOW2 Format = "qcow2"
	FormatVMDK  Format = "vmdk"
	FormatVHDX  Format = "vhdx"
	FormatRaw   Format = "raw"
	FormatOther Format = "other"
)

// FormatOf guesses the format from a filename extension. The registry records
// it so a hypervisor driver knows whether it can consume an image directly
// (a VMware driver wants OVA/VMDK; a KVM driver wants qcow2/raw).
func FormatOf(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".iso":
		return FormatISO
	case ".ova":
		return FormatOVA
	case ".ovf":
		return FormatOVF
	case ".qcow2", ".qcow":
		return FormatQCOW2
	case ".vmdk":
		return FormatVMDK
	case ".vhdx", ".vhd":
		return FormatVHDX
	case ".raw", ".img":
		return FormatRaw
	default:
		return FormatOther
	}
}

// Image is one catalogued decoy image.
type Image struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Format     Format     `json:"format"`
	Difficulty Difficulty `json:"difficulty"`
	// Persona hints at what the image portrays (e.g. "linux/web"), so the
	// planner and drivers can present it consistently.
	Persona string `json:"persona,omitempty"`
	// Source records provenance: "htb", "vulnhub", "custom", a vendor name.
	// HackTheBox and similar images are third-party IP — the operator imports
	// their own copy; MIRAGE never ships them.
	Source string `json:"source,omitempty"`
	// SHA256 pins the exact bytes, so a swapped or corrupted image is caught.
	SHA256      string    `json:"sha256,omitempty"`
	SizeBytes   int64     `json:"size_bytes,omitempty"`
	Sanitized   bool      `json:"sanitized"`
	SanitizedAt time.Time `json:"sanitized_at,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	AddedAt     time.Time `json:"added_at"`
}

// Catalog is a JSON-backed registry of images.
type Catalog struct {
	mu     sync.Mutex
	path   string
	images map[string]*Image
}

// Open loads (or starts) a catalog at path.
func Open(path string) (*Catalog, error) {
	c := &Catalog{path: path, images: map[string]*Image{}}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Catalog) load() error {
	raw, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("catalog: read %s: %w", c.path, err)
	}
	var list []*Image
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("catalog: parse %s: %w", c.path, err)
	}
	for _, im := range list {
		c.images[im.ID] = im
	}
	return nil
}

func (c *Catalog) saveLocked() error {
	list := make([]*Image, 0, len(c.images))
	for _, im := range c.images {
		list = append(list, im)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].AddedAt.Before(list[j].AddedAt) })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// ImportOptions parametrise an import.
type ImportOptions struct {
	Name       string
	Difficulty Difficulty
	Persona    string
	Source     string
	Tags       []string
	Notes      string
	// Checksum computes the SHA-256 of the image. It is worth it (it pins the
	// bytes) but can be slow on a huge image, so it is optional.
	Checksum bool
}

// Import registers an existing image file. It records metadata and, optionally,
// a checksum; it never copies or moves the file.
func (c *Catalog) Import(path string, opts ImportOptions) (*Image, error) {
	if opts.Difficulty == "" {
		opts.Difficulty = Medium
	}
	if !opts.Difficulty.Valid() {
		return nil, fmt.Errorf("catalog: invalid difficulty %q (want easy|medium|hard|insane)", opts.Difficulty)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: image %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("catalog: %s is a directory, not an image", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	name := opts.Name
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	im := &Image{
		ID:         newID(name),
		Name:       name,
		Path:       abs,
		Format:     FormatOf(path),
		Difficulty: opts.Difficulty,
		Persona:    opts.Persona,
		Source:     opts.Source,
		SizeBytes:  info.Size(),
		Tags:       opts.Tags,
		Notes:      opts.Notes,
		AddedAt:    time.Now(),
	}
	if opts.Checksum {
		sum, err := checksum(path)
		if err != nil {
			return nil, err
		}
		im.SHA256 = sum
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.images[im.ID]; exists {
		im.ID = im.ID + "-" + shortRand()
	}
	c.images[im.ID] = im
	if err := c.saveLocked(); err != nil {
		delete(c.images, im.ID)
		return nil, err
	}
	return im, nil
}

// Get returns an image by id.
func (c *Catalog) Get(id string) (*Image, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	im, ok := c.images[id]
	if !ok {
		return nil, false
	}
	cp := *im
	return &cp, true
}

// Filter narrows a listing. Empty fields match everything.
type Filter struct {
	Difficulty Difficulty
	Persona    string
	Source     string
	// SanitizedOnly returns only images cleared for deployment.
	SanitizedOnly bool
}

// List returns images matching the filter, oldest first.
func (c *Catalog) List(f Filter) []*Image {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Image, 0, len(c.images))
	for _, im := range c.images {
		if f.Difficulty != "" && im.Difficulty != f.Difficulty {
			continue
		}
		if f.Persona != "" && im.Persona != f.Persona {
			continue
		}
		if f.Source != "" && im.Source != f.Source {
			continue
		}
		if f.SanitizedOnly && !im.Sanitized {
			continue
		}
		cp := *im
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddedAt.Before(out[j].AddedAt) })
	return out
}

// Remove forgets an image entry. It does NOT delete the file: the operator owns
// the bytes and may still want them.
func (c *Catalog) Remove(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.images[id]; !ok {
		return fmt.Errorf("catalog: no image %q", id)
	}
	delete(c.images, id)
	return c.saveLocked()
}

// Retag changes an image's difficulty and/or tags. Empty difficulty leaves it.
func (c *Catalog) Retag(id string, d Difficulty, tags []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	im, ok := c.images[id]
	if !ok {
		return fmt.Errorf("catalog: no image %q", id)
	}
	if d != "" {
		if !d.Valid() {
			return fmt.Errorf("catalog: invalid difficulty %q", d)
		}
		im.Difficulty = d
	}
	if tags != nil {
		im.Tags = tags
	}
	return c.saveLocked()
}

// MarkSanitized records that an image has passed sanitisation and is safe to
// deploy. Only a sanitised image should become a live decoy.
func (c *Catalog) MarkSanitized(id string, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	im, ok := c.images[id]
	if !ok {
		return fmt.Errorf("catalog: no image %q", id)
	}
	im.Sanitized = true
	im.SanitizedAt = at
	return c.saveLocked()
}

// checksum streams the file through SHA-256 without buffering it whole.
func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shortRand() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newID(name string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == ' ' || r == '_' || r == '.' || r == '/':
			return '-'
		default:
			return -1
		}
	}, name)
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "image"
	}
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return slug
}
